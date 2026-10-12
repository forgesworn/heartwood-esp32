"""Offline host evidence only: pinned SDK, public fixtures, separate cold processes.

This first bounded campaign covers worst-case record 32 for both insertion orders.
It is not the complete lifecycle/recovery-init/GC/full-refusal acceptance matrix.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

BYTES = 262144
NOT_FOUND = 0x1102


def sha(data):
    return hashlib.sha256(data).hexdigest()


def frames(profile, generation, records):
    result = {"anchor": profile["anchor"]}
    for g in ([1] if generation == 1 else [generation - 1, generation]):
        s = profile["snapshots"][g - 1]
        result[f"snap{s['slot']}"] = s["sealed"]
    for n in range(1, records + 1):
        result[f"m{n:02}"] = profile["manifests"][n - 1]["sealed"]
    return result


def recipe(profiles, order):
    subjects = []
    for index, p in enumerate(profiles):
        nmax = 31 if index == 7 else 32
        ops = [(p["namespace"], "anchor", p["anchor"]), (p["namespace"], "snap0", p["snapshots"][0]["sealed"])]
        for n in range(1, nmax + 1):
            ops.append((p["namespace"], f"m{n:02}", p["manifests"][n - 1]["sealed"]))
            for g in [2 * n, 2 * n + 1]:
                s = p["snapshots"][g - 1]
                ops.append((p["namespace"], f"snap{s['slot']}", s["sealed"]))
        if index != 7:
            for g in range(66, 130):
                s = p["snapshots"][g - 1]
                ops.append((p["namespace"], f"snap{s['slot']}", s["sealed"]))
        subjects.append(ops)
    if order == "subject-major":
        return [op for ops in subjects for op in ops]
    return [ops[i] for i in range(max(map(len, subjects))) for ops in subjects if i < len(ops)]


class Runner:
    def __init__(self, args, profiles):
        self.args = args
        self.profiles = profiles
        self.count = 0
        self.work = args.scratch / "runs"
        self.work.mkdir(parents=True, exist_ok=False)
        self.query = args.scratch / "names.txt"
        self.query.write_text("\n".join(p["namespace"] for p in profiles) + "\n")
        self.archive = gzip.open(args.evidence / "allocation-nvs-cold-worst32-traces.jsonl.gz", "xt", compresslevel=6)

    def run(self, image, ops, mode="none", cut=0):
        self.count += 1
        work = self.work / str(self.count)
        work.mkdir()
        baseline = work / "input.bin"
        if image is not None:
            assert len(image) == BYTES
            baseline.write_bytes(image)
        operation = work / "ops.txt"
        operation.write_text("".join(" ".join(op) + "\n" for op in ops))
        output = work / "output.bin"
        inventory = work / "inventory.json"
        trace = work / "trace.jsonl"
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        command = [str(self.args.worker), str(baseline) if image is not None else "-", str(output), str(operation), str(inventory), str(self.query), mode, str(cut), str(trace)]
        r = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        assert r.returncode in (0, 90, 91), (r.returncode, r.stdout.decode(), r.stderr.decode())
        raw = output.read_bytes()
        assert len(raw) == BYTES
        events = [json.loads(line) for line in trace.read_text().splitlines()]
        captured = json.loads(inventory.read_text()) if inventory.exists() else None
        data = {"run": self.count, "mode": mode, "cut": cut, "returnCode": r.returncode, "inputSHA256": sha(image) if image is not None else None, "outputSHA256": sha(raw), "trace": events, "inventorySHA256": sha(inventory.read_bytes()) if inventory.exists() else None}
        self.archive.write(json.dumps(data, separators=(",", ":")) + "\n")
        self.archive.flush()
        shutil.rmtree(work)
        return raw, captured, events, r.returncode

    def cold(self, image):
        raw, capture, events, code = self.run(image, [])
        assert code == 0 and capture["initStatus"] == 0 and capture["operationStatus"] == 0
        assert len(capture["namespaces"]) == 8
        result = []
        for p, ns in zip(self.profiles, capture["namespaces"]):
            assert ns["namespace"] == p["namespace"]
            assert ns["openStatus"] == 0 and ns["enumerationStatus"] == NOT_FOUND
            entries = ns["entries"]
            assert len({e["key"] for e in entries}) == len(entries)
            assert all(e["type"] == 0x42 and len(bytes.fromhex(e["hex"])) == e["size"] for e in entries)
            result.append({e["key"]: e["hex"] for e in entries})
        return raw, capture, result, events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    assert args.scratch.resolve().is_relative_to(Path.home() / "WebstormProjects/.worktrees")
    args.scratch.mkdir(parents=True, exist_ok=False)
    profiles = json.loads(args.fixtures.read_text())["subjects"]
    assert len(profiles) == 8
    runner = Runner(args, profiles)
    summary = {"scope": "bounded worst-record32 cold campaign, host only", "orders": [], "completeRequiredCapacityAcceptance": False, "capacityAuthority": False, "runtimeActivation": False, "physicalAcceptance": False, "fixtureSHA256": sha(args.fixtures.read_bytes()), "workerSHA256": sha(args.worker.read_bytes())}
    case_count = 0
    with (args.evidence / "allocation-nvs-cold-worst32-codec-input.jsonl").open("x") as codec:
        for order in ["subject-major", "interleaved"]:
            start = time.monotonic()
            ops = recipe(profiles, order)
            raw, capture, trace, code = runner.run(None, ops)
            population_erases = capture["sectorErases"] if capture else None
            ordinary, ordinary_capture, _, ordinary_code = runner.run(None, ops, "ordinary")
            assert code == ordinary_code == 0 and raw == ordinary, "instrumentation changed successful flash bytes"
            raw, capture, actual, recovery = runner.cold(raw)
            expected = [frames(p, 63 if i == 7 else 129, 31 if i == 7 else 32) for i, p in enumerate(profiles)]
            assert actual == expected
            assert capture["used"] == 4002 and capture["namespaceCount"] == 8
            (args.evidence / f"allocation-nvs-cold-worst32-{order}-baseline.bin").write_bytes(raw)
            record = {"order": order, "baselineSHA256": sha(raw), "successfulInstrumentationByteIdentical": True, "baselineUsedEntries": capture["used"], "populationSectorErases": population_erases, "populationTraceSectorErases": sum(e.get("kind") == "erase" and e.get("status") == 0 for e in trace), "stages": []}
            # Same retained manifests, different write order and real GC history.
            p = profiles[7]
            additions = [(p["namespace"], "m32", p["manifests"][31]["sealed"])]
            additions += [(p["namespace"], f"snap{p['snapshots'][g-1]['slot']}", p["snapshots"][g - 1]["sealed"]) for g in [64, 65]]
            specs = [{"generations": [62, 63], "records": 31}, {"generations": [62, 63], "records": 32}, {"generations": [63, 64], "records": 32}, {"generations": [64, 65], "records": 32}]
            for stage, operation in enumerate(additions):
                old = dict(expected[7])
                new = dict(old)
                new[operation[1]] = operation[2]
                normal, normal_capture, events, status = runner.run(raw, [operation])
                assert status == 0
                normal, cold_capture, normal_actual, _ = runner.cold(normal)
                wanted = expected[:7] + [new]
                assert normal_actual == wanted
                logical = [e["logical"] for e in events if "logical" in e and e["status"] == 0]
                primitive = [e["primitive"] for e in events if "primitive" in e]
                stage_record = {"key": operation[1], "wordCuts": len(primitive), "logicalCuts": len(logical), "transientCuts": len(primitive) + 1, "sdkErrors": 0, "errorWithExactNew": 0, "erases": sum(e.get("kind") == "erase" for e in events)}
                for mode, cuts in [("word", primitive), ("logical", logical), ("transient", range(len(primitive) + 1))]:
                    for cut in cuts:
                        interrupted, failed_capture, fault_events, code = runner.run(raw, [operation], mode, cut)
                        if mode != "transient":
                            assert code == 90
                        recovered, observed, inventories, recovery_events = runner.cold(interrupted)
                        # Every previously retained immutable frame and all other
                        # histories survive. A replaced slot may be absent (HOLD).
                        assert inventories[:7] == expected[:7], (order, stage, mode, cut, "other history loss")
                        retained = {k: v for k, v in old.items() if k != operation[1]}
                        assert all(inventories[7].get(k) == v for k, v in retained.items()), (order, stage, mode, cut, "non-target retained history loss")
                        for key, value in inventories[7].items():
                            assert key in new and value in {old.get(key), new[key]}, (order, stage, mode, cut, key, "unexpected stored frame")
                        c = {"profile": 7, "initStatus": observed["initStatus"], "namespace": observed["namespaces"][7], "old": specs[stage], "new": specs[stage + 1], "order": order, "stage": stage, "mode": mode, "cut": cut, "flashSHA256": sha(interrupted), "recoveredSHA256": sha(recovered), "sourceReturnCode": code, "sourceStatus": failed_capture.get("operationStatus") if failed_capture else None}
                        if inventories[7] == old:
                            c["expectedClass"] = "exact-old"
                        elif inventories[7] == new:
                            c["expectedClass"] = "exact-new"
                        else:
                            c["expectedClass"] = "HOLD"
                        codec.write(json.dumps(c, separators=(",", ":")) + "\n")
                        case_count += 1
                        if code == 91:
                            stage_record["sdkErrors"] += 1
                            if inventories[7] == new:
                                stage_record["errorWithExactNew"] += 1
                raw, expected[7] = normal, new
                record["stages"].append(stage_record)
                print(order, stage_record, "classified inputs", case_count, flush=True)
            record["elapsedSeconds"] = round(time.monotonic() - start, 2)
            summary["orders"].append(record)
    runner.archive.close()
    summary["codecInputCases"] = case_count
    summary["freshProcesses"] = runner.count
    summary["codecClassificationVerified"] = False
    (args.evidence / "allocation-nvs-cold-worst32-campaign.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
