"""Convert periodic counter samples to 4-bit history-bit records."""

import json

from engine.periodic_counter import OUTPUT_BITS, PERIODIC_COUNTER_MODES

NIBBLE_SPACE = 2 ** OUTPUT_BITS


def transform_records(records):
    """Copy validated periodic counter values directly into bit records."""
    transformed = []
    for record in records:
        if record.get("counter_mode") not in PERIODIC_COUNTER_MODES:
            raise ValueError("History bits require a periodic counter record")

        counter = record.get("counter")
        if (
            isinstance(counter, bool)
            or not isinstance(counter, int)
            or not 0 <= counter < NIBBLE_SPACE
        ):
            raise ValueError("Periodic counter must be a 4-bit integer")

        transformed.append({
            "sample_no": record.get("sample_no"),
            "protocol": record.get("protocol"),
            "timestamp": record.get("timestamp"),
            "counter": counter,
            "bit_value": counter,
        })
    return transformed


def transform_json_file(input_path, output_path, verbose=True):
    """Read periodic history and write its direct 4-bit counter values."""
    with open(input_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    if data.get("counter_mode") not in PERIODIC_COUNTER_MODES:
        raise ValueError(
            "Only periodic counter history is supported; PoI-derived packet "
            "history cannot be converted to history bits."
        )

    samples = transform_records(data.get("samples", []))
    output = {
        "source_file": input_path,
        "interface": data.get("interface"),
        "counter_mode": data["counter_mode"],
        "counter_interval_seconds": data.get("counter_interval_seconds"),
        "initialization_time": data.get("initialization_time"),
        "total_packets": None,
        "total_counter_samples": data.get("total_counter_samples", len(samples)),
        "mapping": "periodic 4-bit counter values",
        "output_bits_per_sample": OUTPUT_BITS,
        "counter_range": [0, NIBBLE_SPACE - 1],
        "counter_table": {
            str(counter): counter for counter in range(NIBBLE_SPACE)
        },
        "samples": samples,
    }

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)

    if verbose:
        print(f"Transformed {len(samples)} periodic counter sample(s).")
        print(f"Saved to {output_path}")

    return output


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python history_bits.py <periodic_history.json> <output.json>")
        sys.exit(1)

    transform_json_file(sys.argv[1], sys.argv[2])
