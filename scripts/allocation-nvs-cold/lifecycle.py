"""Public offline creation/first-append/final-retirement SDK cold-cut evidence.

Every readable all-subject capture goes through the actual codec on both curves.
This campaign does not issue genesis, capacity, witness or controller authority.
"""
import argparse
import json
from pathlib import Path
import time

from recovery import ERRORS, StrictRunner, integer, retained, successful_calls_before_inventory
from worst32 import BYTES, NOT_FOUND, frames, recipe, sha

FIXTURE = "004de00927289a9dde56b03e2e172659e9124510027ec6a6dd5ad05db9586bdd"  # pragma: allow-secret; public fixture SHA256
TERMINAL = "exact-final-retirement-promoted"
SPECS = {
    "empty-namespace-HOLD": ([], 0, False),
    "anchor-only-HOLD": ([], 0, True),
    "exact-local-genesis": ([1], 0, True),
    "exact-orphan-first": ([1], 1, True),
    "exact-first-pending": ([1, 2], 1, True),
    "exact-first-promoted": ([2, 3], 1, True),
    "exact-pre-final-retirement": ([126, 127], 32, True),
    "exact-final-retirement-pending": ([127, 128], 32, True),
    TERMINAL: ([128, 129], 32, True),
}


def state(p, label):
    if label == "absent-HOLD":
        return None
    generations, records, anchor = SPECS[label]
    result = {"anchor": p["anchor"]} if anchor else {}
    for generation in generations:
        s = p["snapshots"][generation - 1]
        result[f"snap{s['slot']}"] = s["sealed"]
    for n in range(1, records + 1):
        result[f"m{n:02}"] = p["manifests"][n - 1]["sealed"]
    return result


class LifecycleRunner(StrictRunner):
    def observe(self, image, allow_absent=False):
        raw, capture, events, code = self.run(image, [])
        if code == 91:
            return raw, capture, None, events, capture["operationStatus"]
        namespaces = capture["namespaces"]
        assert len(namespaces) == 8
        inventories, errors = [], []
        for index, (p, ns) in enumerate(zip(self.profiles, namespaces)):
            assert ns["namespace"] == p["namespace"]
            opened, end = integer(ns["openStatus"]), integer(ns["enumerationStatus"])
            if index == 7 and allow_absent and opened == end == NOT_FOUND and ns["entries"] == []:
                inventories.append(None)
                continue
            if opened != 0 or end != NOT_FOUND:
                assert opened == 0 or opened in ERRORS
                assert end in ERRORS
                errors.append(opened or end)
                continue
            entries, inventory = ns["entries"], {}
            assert len(entries) <= 35
            for e in entries:
                key, value = e["key"], e["hex"]
                assert key in {"anchor", "snap0", "snap1", *(f"m{n:02}" for n in range(1, 33))}
                assert key not in inventory and type(value) is str
                width = 476 if key == "anchor" else 498 if key.startswith("snap") else 356
                assert e["type"] == 0x42 and e["size"] == width
                assert len(value) == width * 2 and all(c in "0123456789abcdef" for c in value)
                inventory[key] = value
            inventories.append(inventory)
        stats = integer(capture["statsStatus"])
        assert stats == 0 or stats in ERRORS
        if errors or stats:
            return raw, capture, None, events, (errors or [stats])[0]
        assert len(inventories) == 8
        return raw, capture, inventories, events, 0


class Emitter:
    def __init__(self, evidence, profiles):
        self.profiles, self.count, self.observations = profiles, 0, 0
        self.stream = (evidence / "lifecycle-codec-input.jsonl").open("x")

    def emit(self, raw, capture, inventories, error, allowed, metadata):
        self.observations += 1
        if error:
            cases = [(7, {"initStatus": error, "namespace": None, "expectedClass": "HOLD", "expectedLocalState": None}, allowed)]
        else:
            cases = []
            for index, actual in enumerate(inventories):
                labels = allowed if index == 7 else [TERMINAL]
                local = next((label for label in labels if actual == state(self.profiles[index], label)), None)
                outcome = local if local is not None and not local.endswith("HOLD") else "HOLD"
                cases.append((index, {"initStatus": 0, "namespace": capture["namespaces"][index], "expectedClass": outcome, "expectedLocalState": local}, labels))
        for index, fields, labels in cases:
            c = dict(metadata, **fields, observation=self.observations, profile=index, allowedLifecycleStates=labels, recoveredSHA256=sha(raw), retentionVerified=error == 0)
            self.stream.write(json.dumps(c, separators=(",", ":")) + "\n")
            self.count += 1
        self.stream.flush()


def retained_lifecycle(actual, others, old, new, target):
    assert actual[:7] == others, "existing terminal history changed"
    if old is None:
        # Namespace-only and still-absent are explicit early HOLD states. They
        # never authorize genesis or bypass checking all seven existing histories.
        assert actual[7] is None or actual[7] in [{}, new]
        return
    assert actual[7] is not None, "previously present target namespace disappeared"
    retained(actual, others, old, new, target)


def cut_stage(runner, emitter, raw, expected, operation, allowed, metadata):
    p = runner.profiles[7]
    old, new = expected[7], dict(expected[7] or {})
    new[operation[1]] = operation[2]
    raw, capture, actual, _, error = runner.observe(raw, allow_absent=old is None)
    assert error == 0 and actual == expected
    emitter.emit(raw, capture, actual, 0, [allowed[0]], dict(metadata, mode="cold-start", flashSHA256=sha(raw)))
    successful, _, events, code = runner.run(raw, [operation])
    assert code == 0
    successful, capture, actual, _, error = runner.observe(successful)
    assert error == 0 and actual == expected[:7] + [new]
    emitter.emit(successful, capture, actual, 0, [allowed[-1]], dict(metadata, mode="uncut", flashSHA256=sha(successful)))
    primitives = [e["primitive"] for e in events if "primitive" in e]
    logical = successful_calls_before_inventory(events)
    record = dict(metadata, wordCuts=len(primitives), logicalCuts=len(logical), transientCuts=len(primitives) + 1, sectorErasePrimitives=[e["primitive"] for e in events if e.get("kind") == "erase"], SDKOperationErrors=0, reconstructionErrors=0, expectedAbsentObservations=0, emptyNamespaceObservations=0)
    for mode, cuts in [("word", primitives), ("logical", logical), ("transient", range(len(primitives) + 1))]:
        for cut in cuts:
            interrupted, failed, fault_trace, code = runner.run(raw, [operation], mode, cut)
            reopened, capture, actual, recovery_trace, error = runner.observe(interrupted, allow_absent=old is None)
            if error:
                record["reconstructionErrors"] += 1
            else:
                retained_lifecycle(actual, expected[:7], old, new, operation[1])
                record["expectedAbsentObservations"] += actual[7] is None
                record["emptyNamespaceObservations"] += actual[7] == {}
            emitter.emit(reopened, capture, actual, error, allowed, dict(metadata, mode=mode, cut=cut, flashSHA256=sha(interrupted), sourceReturnCode=code, sourceStatus=failed.get("operationStatus") if failed else None))
            if code == 91:
                record["SDKOperationErrors"] += 1
            # Persist real SDK namespace creation from the abrupt RW-open cut.
            if old is None and mode == "logical" and code == 90 and not error and actual[7] == {}:
                assert fault_trace[-1]["call"] == "open_readwrite"
                assert fault_trace[-1]["logical"] == cut and fault_trace[-1]["status"] == 0
                name = f"{metadata['order']}-namespace-only-logical-{cut}.bin"
                (runner.args.evidence / name).write_bytes(interrupted)
                record.setdefault("namespaceOnlyEvidence", []).append(dict(file=name, SHA256=sha(interrupted), logical=cut, boundary="open_readwrite"))
    if old is None:
        assert record["emptyNamespaceObservations"] > 0, "empty namespace transition was not observed"
        assert record.get("namespaceOnlyEvidence"), "missing real SDK RW-open boundary evidence"
        for proof in record["namespaceOnlyEvidence"]:
            persisted = (runner.args.evidence / proof["file"]).read_bytes()
            assert len(persisted) == BYTES and sha(persisted) == proof["SHA256"]
    print(record, "codec records", emitter.count, flush=True)
    return successful, expected[:7] + [new], record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["worker", "fixtures", "scratch", "evidence"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    assert args.scratch.resolve().is_relative_to(Path.home() / "WebstormProjects/.worktrees") and not args.scratch.is_symlink()
    args.scratch.mkdir(parents=True, exist_ok=False)
    args.evidence.mkdir(parents=True, exist_ok=False)
    assert sha(args.fixtures.read_bytes()) == FIXTURE
    profiles = json.loads(args.fixtures.read_text())["subjects"]
    assert len(profiles) == 8
    runner = LifecycleRunner(args, profiles, "lifecycle-traces.jsonl.gz")
    emitter = Emitter(args.evidence, profiles)
    summary = dict(scope="bounded creation/first-append/final-retirement host cuts", fixtureSHA256=FIXTURE, workerSHA256=sha(args.worker.read_bytes()), orders=[], codecClassificationVerified=False, capacityAuthority=False, runtimeActivation=False, physicalAcceptance=False, completeRequiredCapacityAcceptance=False, transitiveClosureProved=False)
    for order in ["subject-major", "interleaved"]:
        start = time.monotonic()
        p = profiles[7]
        population = [op for op in recipe(profiles, order) if op[0] != p["namespace"]]
        raw, _, _, code = runner.run(None, population)
        ordinary, _, _, ordinary_code = runner.run(None, population, "ordinary")
        assert code == ordinary_code == 0 and raw == ordinary
        raw, capture, actual, _, error = runner.observe(raw, allow_absent=True)
        expected = [frames(f, 129, 32) for f in profiles[:7]] + [None]
        assert error == 0 and actual == expected
        (args.evidence / f"{order}-seven-terminal-baseline.bin").write_bytes(raw)
        emitter.emit(raw, capture, actual, 0, ["absent-HOLD"], dict(order=order, phase="target-absent", mode="baseline", flashSHA256=sha(raw)))
        stages = []
        sequence = [
            ("anchor", p["anchor"], ["absent-HOLD", "empty-namespace-HOLD", "anchor-only-HOLD"]),
            ("snap0", p["snapshots"][0]["sealed"], ["anchor-only-HOLD", "exact-local-genesis"]),
            ("m01", p["manifests"][0]["sealed"], ["exact-local-genesis", "exact-orphan-first"]),
            ("snap1", p["snapshots"][1]["sealed"], ["exact-orphan-first", "exact-first-pending"]),
            ("snap0", p["snapshots"][2]["sealed"], ["exact-first-pending", "exact-first-promoted"]),
        ]
        for key, value, allowed in sequence:
            raw, expected, result = cut_stage(runner, emitter, raw, expected, (p["namespace"], key, value), allowed, dict(order=order, phase=allowed[-1], targetKey=key))
            stages.append(result)
        assert expected[7] == state(p, "exact-first-promoted")

        # The terminal baseline uses the same seven permanent histories, with
        # eighth history replayed through g127 (retirement31 promotion).
        eighth = []
        eighth.append((p["namespace"], "anchor", p["anchor"]))
        eighth.append((p["namespace"], "snap0", p["snapshots"][0]["sealed"]))
        for n in range(1, 33):
            eighth.append((p["namespace"], f"m{n:02}", p["manifests"][n - 1]["sealed"]))
            for g in [2 * n, 2 * n + 1]:
                s = p["snapshots"][g - 1]
                eighth.append((p["namespace"], f"snap{s['slot']}", s["sealed"]))
        for g in range(66, 128):
            s = p["snapshots"][g - 1]
            eighth.append((p["namespace"], f"snap{s['slot']}", s["sealed"]))
        histories = [[op for op in population if op[0] == f["namespace"]] for f in profiles[:7]] + [eighth]
        terminal_recipe = [op for ops in histories for op in ops] if order == "subject-major" else [op for i in range(max(map(len, histories))) for ops in histories for op in ops[i:i+1]]
        raw, _, _, code = runner.run(None, terminal_recipe)
        ordinary, _, _, ordinary_code = runner.run(None, terminal_recipe, "ordinary")
        assert code == ordinary_code == 0 and raw == ordinary
        raw, capture, actual, _, error = runner.observe(raw)
        expected = [frames(f, 129, 32) for f in profiles[:7]] + [state(p, "exact-pre-final-retirement")]
        assert error == 0 and actual == expected
        (args.evidence / f"{order}-pre-final-retirement-baseline.bin").write_bytes(raw)
        emitter.emit(raw, capture, actual, 0, ["exact-pre-final-retirement"], dict(order=order, phase="pre-final-retirement", mode="baseline", flashSHA256=sha(raw)))
        for g, allowed in [(128, ["exact-pre-final-retirement", "exact-final-retirement-pending"]), (129, ["exact-final-retirement-pending", TERMINAL])]:
            s = p["snapshots"][g - 1]
            raw, expected, result = cut_stage(runner, emitter, raw, expected, (p["namespace"], f"snap{s['slot']}", s["sealed"]), allowed, dict(order=order, phase=allowed[-1], targetKey=f"snap{s['slot']}"))
            stages.append(result)
        (args.evidence / f"{order}-all-terminal-baseline.bin").write_bytes(raw)
        summary["orders"].append(dict(order=order, successfulInstrumentationByteIdentical=True, stages=stages, elapsedSeconds=round(time.monotonic() - start, 2)))
    emitter.stream.close()
    runner.archive.close()
    summary.update(freshProcesses=runner.count, completeObservations=emitter.observations, codecInputRecords=emitter.count, codecInputSHA256=sha((args.evidence / "lifecycle-codec-input.jsonl").read_bytes()))
    (args.evidence / "lifecycle-campaign.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
