"""Offline fixed record32 reconciliation and finite repeated cold-init cuts.

Only public fixtures and the pinned host SDK worker. No witness/controller action.
Recovery exploration is deliberately depth/edge bounded, never closure proof.
"""
import argparse
from collections import deque
import json
from pathlib import Path
import time

from worst32 import BYTES, NOT_FOUND, Runner, frames, recipe, sha

STATES = {
    "exact-orphan": (63, 32),
    "exact-pending": (64, 32),
    "exact-promoted": (65, 32),
}
# Error values declared by the pinned nvs.h / esp_err.h / spi_flash headers.
ERRORS = {-1, *range(0x101, 0x10B), *range(0x1101, 0x111A), 0x6001, 0x6002}


def integer(value):
    assert type(value) is int, "non-integer worker status/counter"
    return value


class StrictRunner(Runner):
    def run(self, image, ops, mode="none", cut=0):
        result = super().run(image, ops, mode, cut)
        raw, capture, trace, code = result
        assert trace, "missing worker trace"
        for kind in ["primitive", "logical"]:
            assert [integer(e[kind]) for e in trace if kind in e] == list(range(1, 1 + sum(kind in e for e in trace)))
        for e in trace:
            status = integer(e["status"])
            assert status == 0 or status in ERRORS, ("unknown SDK error", e)
            if "primitive" in e:
                assert e["kind"] in {"write", "write_raw", "erase"}
                offset, size = integer(e["offset"]), integer(e["size"])
                assert offset >= 0 and offset + size <= BYTES
                assert (size == 4096 and offset % 4096 == 0) if e["kind"] == "erase" else (size == 4 and offset % 4 == 0)
        if code == 90:
            assert mode in {"word", "logical"} and capture is None
            event = trace[-1]
            counter = "primitive" if mode == "word" else "logical"
            assert event.get(counter) == cut and event["status"] == 0
        elif code == 91:
            assert capture is not None and integer(capture["operationStatus"]) in ERRORS
            assert integer(capture["initStatus"]) == 0 or capture["initStatus"] in ERRORS
            assert "namespaces" not in capture, "post-error partial inventory"
        else:
            assert code == 0 and capture is not None
            assert integer(capture["initStatus"]) == integer(capture["operationStatus"]) == 0
        # Preserve every complete/failed capture, not just target codec inputs or
        # a hash: an independent reviewer can audit all eight retained histories.
        self.archive.write(json.dumps({"kind": "capture", "run": self.count, "capture": capture}, separators=(",", ":")) + "\n")
        self.archive.flush()
        return raw, capture, trace, code

    def observe(self, image):
        raw, capture, events, code = self.run(image, [])
        if code == 91:
            return raw, capture, None, events, capture["operationStatus"]
        namespaces = capture["namespaces"]
        assert len(namespaces) == 8
        inventories = []
        errors = []
        for p, ns in zip(self.profiles, namespaces):
            assert ns["namespace"] == p["namespace"]
            opened = integer(ns["openStatus"])
            end = integer(ns["enumerationStatus"])
            if opened != 0 or end != NOT_FOUND:
                assert opened == 0 or opened in ERRORS
                assert end in ERRORS
                errors.append(opened or end)
                continue
            entries = ns["entries"]
            assert len(entries) <= 35
            inventory = {}
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
            # Total failure: never feed a successful namespace from a partial
            # all-subject capture into Rust as if reconstruction had completed.
            return raw, capture, None, events, (errors or [stats])[0]
        assert len(inventories) == 8
        return raw, capture, inventories, events, 0


def retained(actual, others, old, new, target):
    assert actual[:7] == others, "other permanent history changed"
    fixed = {k: v for k, v in old.items() if k != target}
    assert all(actual[7].get(k) == v for k, v in fixed.items()), "non-target retained key changed/missing"
    for key, value in actual[7].items():
        assert key in new and value in {old.get(key), new[key]}, "unexpected target history bytes"


def state_name(actual, p, allowed):
    for label in allowed:
        generation, count = STATES[label]
        if actual == frames(p, generation, count):
            return label
    return "HOLD"


def successful_calls_before_inventory(trace):
    # Reconciliation boundaries are init/open/set/commit/readback/close. Read-only
    # inventory boundaries were covered by worst32; these are recovery/write cuts.
    end = next(e["logical"] for e in trace if e.get("call") == "open_readonly")
    return [e["logical"] for e in trace if "logical" in e and e["logical"] < end and e["status"] == 0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["worker", "fixtures", "scratch", "evidence"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-edges", type=int, default=2048)
    args = parser.parse_args()
    assert 1 <= args.max_depth <= 3 and 1 <= args.max_edges <= 10000
    assert args.scratch.resolve().is_relative_to(Path.home() / "WebstormProjects/.worktrees")
    assert not args.scratch.is_symlink()
    args.scratch.mkdir(parents=True, exist_ok=False)
    profiles = json.loads(args.fixtures.read_text())["subjects"]
    assert len(profiles) == 8 and all(p["root"] == f"{i+1:02x}" * 32 for i, p in enumerate(profiles))
    assert sha(args.fixtures.read_bytes()) == "004de00927289a9dde56b03e2e172659e9124510027ec6a6dd5ad05db9586bdd"  # pragma: allow-secret; public fixture SHA256
    args.evidence.mkdir(parents=True, exist_ok=False)
    runner = StrictRunner(args, profiles, "recovery-traces.jsonl.gz")
    codec = (args.evidence / "recovery-codec-input.jsonl").open("x")
    graph = (args.evidence / "recovery-graph.jsonl").open("x")
    summary = {"scope": "fixed record32 host reconciliation and finite cold-init cut graph", "fixtureSHA256": sha(args.fixtures.read_bytes()), "workerSHA256": sha(args.worker.read_bytes()), "maxDepth": args.max_depth, "maxEdgesPerOrder": args.max_edges, "orders": [], "capacityAuthority": False, "physicalAcceptance": False, "runtimeActivation": False, "completeRequiredCapacityAcceptance": False, "transitiveClosureProved": False, "codecClassificationVerified": False}
    cases = 0

    def emit(raw, capture, inventories, error, allowed, metadata):
        nonlocal cases
        c = dict(metadata, profile=7, allowedStates=allowed, recoveredSHA256=sha(raw), retentionVerified=error == 0)
        if error:
            c.update(initStatus=error, namespace=None, expectedClass="HOLD", totalReconstructionError=error)
        else:
            c.update(initStatus=0, namespace=capture["namespaces"][7], expectedClass=state_name(inventories[7], profiles[7], allowed))
        codec.write(json.dumps(c, separators=(",", ":")) + "\n")
        codec.flush()
        cases += 1

    for order in ["subject-major", "interleaved"]:
        start = time.monotonic()
        record = {"order": order, "stages": [], "seeds": [], "graphEdges": 0, "cyclesOrDuplicateImages": 0, "depthLimitedImages": 0, "edgeBudgetReached": False, "reconstructionErrors": 0}
        raw, _, _, code = runner.run(None, recipe(profiles, order))
        ordinary, _, _, ordinary_code = runner.run(None, recipe(profiles, order), "ordinary")
        assert code == ordinary_code == 0 and raw == ordinary, "instrumentation changed population bytes"
        raw, capture, actual, _, error = runner.observe(raw)
        expected = [frames(p, 63 if i == 7 else 129, 31 if i == 7 else 32) for i, p in enumerate(profiles)]
        assert error == 0 and actual == expected
        p = profiles[7]
        raw, _, _, code = runner.run(raw, [(p["namespace"], "m32", p["manifests"][31]["sealed"])])
        assert code == 0
        raw, capture, actual, _, error = runner.observe(raw)
        expected[7] = frames(p, 63, 32)
        assert error == 0 and actual == expected
        (args.evidence / f"{order}-orphan-baseline.bin").write_bytes(raw)
        emit(raw, capture, actual, 0, ["exact-orphan"], {"order": order, "phase": "cold-orphan", "flashSHA256": sha(raw)})
        seeds = []
        for generation, phase, allowed in [
            (64, "orphan-to-pending", ["exact-orphan", "exact-pending"]),
            (65, "pending-to-promoted", ["exact-pending", "exact-promoted"]),
        ]:
            # Begin every operation from a separately reconstructed cold image.
            raw, cold, actual, _, error = runner.observe(raw)
            assert error == 0 and actual == expected
            emit(raw, cold, actual, 0, [allowed[0]], {"order": order, "phase": phase + "-cold-start", "flashSHA256": sha(raw)})
            s = p["snapshots"][generation - 1]
            op = (p["namespace"], f"snap{s['slot']}", s["sealed"])
            old, new = dict(expected[7]), frames(p, generation, 32)
            normal, _, trace, code = runner.run(raw, [op])
            assert code == 0
            normal, normal_capture, normal_actual, _, error = runner.observe(normal)
            assert error == 0 and normal_actual == expected[:7] + [new]
            emit(normal, normal_capture, normal_actual, 0, [allowed[1]], {"order": order, "phase": phase + "-uncut", "flashSHA256": sha(normal)})
            primitive = [e["primitive"] for e in trace if "primitive" in e]
            logical = successful_calls_before_inventory(trace)
            erase_cuts = [e["primitive"] for e in trace if e.get("kind") == "erase"]
            # Fixed deterministic seed rule, not selected by observed success.
            selected = {primitive[len(primitive) // 2], *(c + d for c in erase_cuts for d in [-1, 0, 1])}
            stage = {"phase": phase, "wordCuts": len(primitive), "logicalCuts": len(logical), "transientCuts": len(primitive) + 1, "sectorErasePrimitives": erase_cuts, "SDKOperationErrors": 0}
            for mode, cuts in [("word", primitive), ("logical", logical), ("transient", range(len(primitive) + 1))]:
                for cut in cuts:
                    interrupted, failed, _, code = runner.run(raw, [op], mode, cut)
                    recovered, observed, inventories, _, error = runner.observe(interrupted)
                    if not error:
                        retained(inventories, expected[:7], old, new, op[1])
                    else:
                        record["reconstructionErrors"] += 1
                    emit(recovered, observed, inventories, error, allowed, {"order": order, "phase": phase, "mode": mode, "cut": cut, "flashSHA256": sha(interrupted), "sourceReturnCode": code, "sourceStatus": failed.get("operationStatus") if failed else None})
                    if code == 91:
                        stage["SDKOperationErrors"] += 1
                    if mode == "word" and cut in selected:
                        name = f"{order}-{phase}-word-{cut}-seed.bin"
                        (args.evidence / name).write_bytes(interrupted)
                        seed = {"order": order, "phase": phase, "targetKey": op[1], "cut": cut, "imageSHA256": sha(interrupted), "file": name, "allowedStates": allowed}
                        record["seeds"].append(seed)
                        seeds.append((interrupted, seed, expected[:7], old, new))
            print(order, stage, "codec cases", cases, flush=True)
            record["stages"].append(stage)
            raw, expected[7] = normal, new

        # A distinct full flash image + intended phase is a graph node. Inventory
        # equality does not collapse flash images with different SDK metadata.
        queue = deque()
        seen = set()
        for image, seed, others, old, new in seeds:
            key = (sha(image), seed["phase"])
            if key not in seen:
                seen.add(key)
                queue.append((image, seed, others, old, new, 0))
        while queue:
            image, seed, others, old, new, depth = queue.popleft()
            parent = sha(image)
            recovered, capture, inventories, trace, error = runner.observe(image)
            if not error:
                retained(inventories, others, old, new, seed["targetKey"])
            else:
                record["reconstructionErrors"] += 1
            emit(recovered, capture, inventories, error, seed["allowedStates"], {"order": order, "phase": seed["phase"], "graphNode": parent, "depth": depth, "mode": "uncut-recovery", "flashSHA256": parent})
            init_at = next(i for i, e in enumerate(trace) if e.get("call") == "init_custom")
            primitives = [e["primitive"] for e in trace[:init_at] if "primitive" in e and e["status"] == 0]
            graph.write(json.dumps({"kind": "node", "imageSHA256": parent, "phase": seed["phase"], "depth": depth, "uncutRecoverySHA256": sha(recovered), "initPrimitiveCuts": len(primitives), "initStatus": capture["initStatus"], "error": error}) + "\n")
            if depth >= args.max_depth:
                if primitives:
                    record["depthLimitedImages"] += 1
                continue
            # Cut every completed cold-init word/erase, plus the successful
            # init API boundary. Never run a writer as part of this graph.
            modes = [("word", c) for c in primitives]
            if capture["initStatus"] == 0:
                modes.append(("logical", trace[init_at]["logical"]))
            for mode, cut in modes:
                if record["graphEdges"] >= args.max_edges:
                    record["edgeBudgetReached"] = True
                    break
                interrupted, _, fault_trace, code = runner.run(image, [], mode, cut)
                assert code == 90
                child = sha(interrupted)
                record["graphEdges"] += 1
                reopened, observed, actual, _, error = runner.observe(interrupted)
                if not error:
                    retained(actual, others, old, new, seed["targetKey"])
                else:
                    record["reconstructionErrors"] += 1
                emit(reopened, observed, actual, error, seed["allowedStates"], {"order": order, "phase": seed["phase"], "graphParent": parent, "depth": depth + 1, "mode": mode, "cut": cut, "flashSHA256": child})
                key = (child, seed["phase"])
                duplicate = key in seen
                graph.write(json.dumps({"kind": "edge", "parentSHA256": parent, "childSHA256": child, "phase": seed["phase"], "parentDepth": depth, "childDepth": depth + 1, "mode": mode, "cut": cut, "traceLast": fault_trace[-1], "duplicate": duplicate, "reconstructionError": error, "retentionVerified": error == 0}) + "\n")
                graph.flush()
                if duplicate:
                    record["cyclesOrDuplicateImages"] += 1
                else:
                    seen.add(key)
                    queue.append((interrupted, seed, others, old, new, depth + 1))
            if record["edgeBudgetReached"]:
                break
        record.update(uniqueGraphImages=len(seen), unexploredQueuedImages=len(queue), elapsedSeconds=round(time.monotonic() - start, 2))
        summary["orders"].append(record)
        print(order, "graph edges", record["graphEdges"], "depth limited", record["depthLimitedImages"], "edge budget", record["edgeBudgetReached"], flush=True)
    codec.close()
    graph.close()
    runner.archive.close()
    summary.update(codecInputCases=cases, freshProcesses=runner.count, codecInputSHA256=sha((args.evidence / "recovery-codec-input.jsonl").read_bytes()), graphSHA256=sha((args.evidence / "recovery-graph.jsonl").read_bytes()))
    (args.evidence / "recovery-campaign.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
