"""Trigger Windows' native DNS-SD registration and mDNS probe sequence."""

import ctypes
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes


DNS_REQUEST_PENDING = 9506
DNS_QUERY_REQUEST_VERSION1 = 1
REGISTRATION_TIMEOUT_SECONDS = 10

_CALLBACK_FACTORY = (
    ctypes.WINFUNCTYPE if os.name == "nt" else ctypes.CFUNCTYPE
)


class _DnsServiceInstance(ctypes.Structure):
    _fields_ = [
        ("pszInstanceName", ctypes.c_wchar_p),
        ("pszHostName", ctypes.c_wchar_p),
        ("ip4Address", ctypes.POINTER(wintypes.ULONG)),
        ("ip6Address", ctypes.c_void_p),
        ("wPort", wintypes.WORD),
        ("wPriority", wintypes.WORD),
        ("wWeight", wintypes.WORD),
        ("dwPropertyCount", wintypes.DWORD),
        ("keys", ctypes.POINTER(ctypes.c_wchar_p)),
        ("values", ctypes.POINTER(ctypes.c_wchar_p)),
        ("dwInterfaceIndex", wintypes.DWORD),
    ]


_RegisterComplete = _CALLBACK_FACTORY(
    None,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(_DnsServiceInstance),
)


class _DnsServiceRegisterRequest(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("InterfaceIndex", wintypes.ULONG),
        ("pServiceInstance", ctypes.POINTER(_DnsServiceInstance)),
        ("pRegisterCompletionCallback", _RegisterComplete),
        ("pQueryContext", ctypes.c_void_p),
        ("hCredentials", ctypes.c_void_p),
        ("unicastEnabled", wintypes.BOOL),
    ]


class NativeMdnsProbeSender:
    """Use Windows DNS-SD registration so Windows emits native mDNS probes.

    Each pointer gets a unique DNS-SD instance name. Windows probes that name
    before announcing the service; the receiver can therefore recognize the
    probe query and treat repeated probes for the same name as one event.
    """

    def __init__(self, iface, source_ip, max_workers=1):
        if os.name != "nt":
            raise RuntimeError(
                "Triggered mDNS mode requires Windows DNS-SD (dnsapi.dll)."
            )

        self.iface = iface
        self.source_ip = source_ip
        self.interface_index = self._interface_index(iface)
        try:
            self._dnsapi = ctypes.WinDLL("dnsapi.dll")
        except OSError as exc:
            raise RuntimeError(
                "Windows DNS-SD API dnsapi.dll is unavailable."
            ) from exc

        self._configure_api()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="native-mdns-probe",
        )
        self._future_lock = threading.Lock()
        self._futures = set()
        self._retained_requests = []

    @staticmethod
    def _interface_index(iface):
        """Resolve Scapy's selected adapter to the Windows interface index."""
        from scapy.all import conf

        try:
            device = conf.ifaces.dev_from_networkname(iface)
        except Exception as exc:
            raise RuntimeError(
                f"Could not map selected adapter {iface!r} to Windows."
            ) from exc

        value = getattr(device, "index", None)
        try:
            index = int(value)
        except (TypeError, ValueError):
            index = 0
        if index <= 0:
            raise RuntimeError(
                f"Selected adapter {iface!r} has no Windows interface index."
            )
        return index

    def _configure_api(self):
        self._dnsapi.DnsServiceConstructInstance.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(wintypes.ULONG),
            ctypes.c_void_p,
            wintypes.WORD,
            wintypes.WORD,
            wintypes.WORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        self._dnsapi.DnsServiceConstructInstance.restype = (
            ctypes.POINTER(_DnsServiceInstance)
        )
        self._dnsapi.DnsServiceFreeInstance.argtypes = [
            ctypes.POINTER(_DnsServiceInstance)
        ]
        self._dnsapi.DnsServiceFreeInstance.restype = None
        self._dnsapi.DnsServiceRegister.argtypes = [
            ctypes.POINTER(_DnsServiceRegisterRequest),
            ctypes.c_void_p,
        ]
        self._dnsapi.DnsServiceRegister.restype = wintypes.DWORD
        self._dnsapi.DnsServiceDeRegister.argtypes = [
            ctypes.POINTER(_DnsServiceRegisterRequest),
            ctypes.c_void_p,
        ]
        self._dnsapi.DnsServiceDeRegister.restype = wintypes.DWORD

    def submit(self, service_name, properties):
        """Schedule a native registration without blocking counter sampling."""
        future = self._executor.submit(
            self._register_and_deregister,
            service_name,
            properties,
        )
        with self._future_lock:
            self._futures.add(future)
        future.add_done_callback(self._forget_future)
        return future

    def _forget_future(self, future):
        with self._future_lock:
            self._futures.discard(future)

    def _register_and_deregister(self, service_name, properties):
        keys = tuple(str(key) for key, _value in properties)
        values = tuple(str(value) for _key, value in properties)
        key_array = (ctypes.c_wchar_p * len(keys))(*keys)
        value_array = (ctypes.c_wchar_p * len(values))(*values)

        host_label = socket.gethostname().split(".", 1)[0].strip(".")
        if not host_label:
            raise RuntimeError("Could not determine the local mDNS host name.")
        host_name = f"{host_label}.local"
        ip4 = wintypes.ULONG(
            int.from_bytes(socket.inet_aton(self.source_ip), "little")
        )
        instance = self._dnsapi.DnsServiceConstructInstance(
            service_name,
            host_name,
            ctypes.byref(ip4),
            None,
            9,
            0,
            0,
            len(keys),
            key_array,
            value_array,
        )
        if not instance:
            raise RuntimeError(
                f"Windows could not construct DNS-SD instance {service_name!r}."
            )

        registration_event = threading.Event()
        deregistration_event = threading.Event()
        callback_lock = threading.Lock()
        callback_state = {"phase": "register", "status": None}

        def registration_complete(status, _context, returned_instance):
            if returned_instance:
                self._dnsapi.DnsServiceFreeInstance(returned_instance)
            with callback_lock:
                callback_state["status"] = int(status)
                phase = callback_state["phase"]
            if phase == "register":
                registration_event.set()
            else:
                deregistration_event.set()

        callback = _RegisterComplete(registration_complete)
        instance.contents.dwInterfaceIndex = self.interface_index
        request = _DnsServiceRegisterRequest(
            Version=DNS_QUERY_REQUEST_VERSION1,
            InterfaceIndex=self.interface_index,
            pServiceInstance=instance,
            pRegisterCompletionCallback=callback,
            pQueryContext=None,
            hCredentials=None,
            unicastEnabled=False,
        )

        registration_settled = False
        registered = False
        deregistration_settled = False
        registration_status = None
        deregistration_status = None
        try:
            status = int(
                self._dnsapi.DnsServiceRegister(ctypes.byref(request), None)
            )
            if status == DNS_REQUEST_PENDING:
                if not registration_event.wait(REGISTRATION_TIMEOUT_SECONDS):
                    raise TimeoutError(
                        f"Timed out registering native mDNS probe "
                        f"{service_name!r}."
                    )
                with callback_lock:
                    status = callback_state["status"]
            registration_settled = True
            if status != 0:
                raise OSError(
                    status,
                    f"Windows DNS-SD registration failed for {service_name!r}",
                )
            registration_status = status
            registered = True

            with callback_lock:
                callback_state["phase"] = "deregister"
                callback_state["status"] = None
            deregistration_event.clear()
            status = int(
                self._dnsapi.DnsServiceDeRegister(ctypes.byref(request), None)
            )
            if status == DNS_REQUEST_PENDING:
                if not deregistration_event.wait(REGISTRATION_TIMEOUT_SECONDS):
                    raise TimeoutError(
                        f"Timed out removing native mDNS probe "
                        f"{service_name!r}."
                    )
                with callback_lock:
                    status = callback_state["status"]
            deregistration_settled = True
            if status != 0:
                raise OSError(
                    status,
                    f"Windows DNS-SD deregistration failed for "
                    f"{service_name!r}",
                )
            deregistration_status = status
            return {
                "service_name": service_name,
                "interface_index": self.interface_index,
                "registration_status": registration_status,
                "deregistration_status": deregistration_status,
                "deregistered": True,
            }
        finally:
            if registration_settled and (not registered or deregistration_settled):
                self._dnsapi.DnsServiceFreeInstance(instance)
            else:
                # Keep ctypes-backed memory and callback alive if Windows may
                # still complete an asynchronous request after our timeout.
                with self._future_lock:
                    self._retained_requests.append(
                        (instance, request, callback, key_array, value_array, ip4)
                    )

    def close(self):
        """Wait for queued native registrations and their cleanup callbacks."""
        self._executor.shutdown(wait=True)
