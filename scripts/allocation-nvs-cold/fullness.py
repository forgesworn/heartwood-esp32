"""Separate raw-SDK artificial fullness; no application capacity semantics.

The unchanged worker queries eight namespaces. Two fresh cold views bind the
eight journals and fixed filler namespace to identical full flash bytes.
"""
import argparse
from copy import copy
import hashlib
import json
from pathlib import Path

from lifecycle import Emitter, FIXTURE, LifecycleRunner, TERMINAL, state
from recovery import ERRORS, StrictRunner, integer
from worst32 import NOT_FOUND, sha

FILLER = "hostfull"
WIDTH = 512
NO_SPACE = 0x1105


class ReconstructionHold(Exception):
    """Recognized SDK read failure; serialized HOLD, never harness success."""


def value(key, version):
    assert key.startswith("f") and len(key) == 5 and key[1:].isdigit()
    assert 0 <= version <= 32
    digest = hashlib.sha256(b"HW public host filler v1\0" + key.encode("ascii") + version.to_bytes(4, "little")).digest()
    return (digest * (WIDTH // 32)).hex()


def entries(ns):
    assert ns["openStatus"] == 0 and ns["enumerationStatus"] == NOT_FOUND
    result = {}
    for e in ns["entries"]:
        assert e["key"] not in result and e["type"] == 0x42
        assert type(e["hex"]) is str and len(e["hex"]) == e["size"] * 2
        assert all(c in "0123456789abcdef" for c in e["hex"])
        result[e["key"]] = e["hex"]
    return result


class FullViews:
    def __init__(self, args, profiles):
        self.args, self.profiles = args, profiles
        journals = copy(args)
        journals.scratch = args.scratch / "journals"
        self.journals = LifecycleRunner(journals, profiles, "fullness-journal-traces.jsonl.gz")
        filler = copy(args)
        filler.scratch = args.scratch / "filler"
        self.filler = StrictRunner(filler, profiles[:7] + [{"namespace": FILLER}], "fullness-filler-traces.jsonl.gz")

    def observe(self, image, wanted, allowed, emitter, metadata):
        raw, capture, journals, events, error = self.journals.observe(image)
        if error:
            self.hold(raw, capture, error, allowed, emitter, metadata, "journals")
        assert journals[:7] == [state(p, TERMINAL) for p in self.profiles[:7]]
        expected_names = [p["namespace"] for p in self.profiles[:7]] + [FILLER]
        view, filler_capture, filler_events, code = self.filler.run(raw, [])
        if code == 91:
            self.hold(view, filler_capture, filler_capture["operationStatus"], allowed, emitter, metadata, "filler")
        assert code == 0 and view == raw, "second cold view changed flash; captures are not the same state"
        stats = integer(filler_capture["statsStatus"])
        if stats != 0:
            assert stats in ERRORS
            self.hold(view, filler_capture, stats, allowed, emitter, metadata, "filler-stats")
        assert len(filler_capture["namespaces"]) == 8
        observed = {}
        for index, ns in enumerate(filler_capture["namespaces"]):
            assert ns["namespace"] == expected_names[index]
            opened, end = integer(ns["openStatus"]), integer(ns["enumerationStatus"])
            expected_absent = index == 7 and wanted is None and opened == end == NOT_FOUND and ns["entries"] == []
            if not expected_absent and (opened != 0 or end != NOT_FOUND):
                assert opened == 0 or opened in ERRORS
                assert end in ERRORS
                self.hold(view, filler_capture, opened or end, allowed, emitter, metadata, "filler-inventory")
            if index < 7:
                assert entries(ns) == journals[index]
            elif wanted is None:
                assert ns["openStatus"] == ns["enumerationStatus"] == NOT_FOUND and ns["entries"] == []
            else:
                observed = entries(ns)
                assert len(observed) <= 2048
                assert all(k.startswith("f") and len(k) == 5 and k[1:].isdigit() and len(v) == WIDTH * 2 for k, v in observed.items())
        emitter.emit(raw, capture, journals, 0, allowed, dict(metadata, flashSHA256=sha(image), secondViewSHA256=sha(view)))
        return raw, journals, observed, events + filler_events

    def hold(self, raw, capture, error, allowed, emitter, metadata, view):
        assert error in ERRORS
        emitter.emit(raw, capture, None, error, allowed, dict(metadata, failedView=view, SDKReconstructionError=error, flashSHA256=sha(raw)))
        emitter.stream.close()
        self.journals.archive.close()
        self.filler.archive.close()
        receipt = dict(metadata, result="HOLD", recognizedSDKError=error, failedView=view, flashSHA256=sha(raw), nativeCapture=capture, retentionVerified=False, campaignComplete=False, capacityAuthority=False, runtimeActivation=False)
        (self.args.evidence / "fullness-reconstruction-HOLD.json").write_text(json.dumps(receipt, indent=2) + "\n")
        raise ReconstructionHold("SDK reconstruction HOLD; retained-data acceptance remains open")


def retained_filler(actual, old, new, target):
    assert all(actual.get(k) == v for k, v in old.items() if k != target), "previous filler key lost/changed"
    assert all(k in new and v in {old.get(k), new[k]} for k, v in actual.items()), "unexpected filler value/key"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["worker", "fixtures", "scratch", "evidence", "baselines"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    assert args.scratch.resolve().is_relative_to(Path.home() / "WebstormProjects/.worktrees") and not args.scratch.is_symlink()
    args.scratch.mkdir(parents=True, exist_ok=False)
    args.evidence.mkdir(parents=True, exist_ok=False)
    assert sha(args.fixtures.read_bytes()) == FIXTURE
    profiles = json.loads(args.fixtures.read_text())["subjects"]
    views = FullViews(args, profiles)
    emitter = Emitter(args.evidence, profiles)
    summary = dict(scope="fixed public filler full/refusal/churn and distinct journal-operation resilience", fixtureSHA256=FIXTURE, workerSHA256=sha(args.worker.read_bytes()), fillerNamespace=FILLER, fillerBytes=WIDTH, fillerSchema="SHA256(domain,key,version) repeated16; f0001..f2048; version0..32", orders=[], codecClassificationVerified=False, capacityAuthority=False, controllerPreMutationRefusalVerified=False, physicalAcceptance=False, completeRequiredCapacityAcceptance=False, runtimeActivation=False)
    for order in ["subject-major", "interleaved"]:
        image = (args.baselines / f"{order}-pre-final-retirement-baseline.bin").read_bytes()
        p = profiles[7]
        pre = state(p, "exact-pre-final-retirement")
        record = dict(order=order, baselineSHA256=sha(image), churnWrites=0, fillerWrites=0, SDKSectorErases=0)
        raw, journals, actual, _ = views.observe(image, None, ["exact-pre-final-retirement"], emitter, dict(order=order, phase="before-filler"))
        assert journals[7] == pre and actual == {}
        wanted = {}

        def write_filler(raw, key, version, phase):
            nonlocal wanted
            blob = value(key, version)
            new = dict(wanted, **{key: blob})
            changed, capture, trace, code = views.journals.run(raw, [(FILLER, key, blob)])
            record["SDKSectorErases"] += sum(e.get("kind") == "erase" and e["status"] == 0 for e in trace)
            changed, journals, actual, _ = views.observe(changed, wanted if wanted else {}, ["exact-pre-final-retirement"], emitter, dict(order=order, phase=phase, attemptedFillerKey=key, version=version, sourceReturnCode=code, sourceStatus=capture.get("operationStatus") if capture else None))
            assert journals[7] == pre
            retained_filler(actual, wanted, new, key)
            if code == 0:
                assert actual == new
                wanted = new
            else:
                assert code == 91
                assert capture["operationStatus"] == NO_SPACE, "fill stopped for a cause other than actual SDK no-space refusal"
                assert actual == wanted or actual == new
                wanted = actual
            return changed, code, capture

        for n in range(1, 17):
            raw, code, _ = write_filler(raw, f"f{n:04}", 0, "filler-seed")
            assert code == 0
            record["fillerWrites"] += 1
        # Deliberate replacement churn exceeds a whole partition of writes.
        # Only observed SDK erase events support the recorded GC evidence.
        for version in range(1, 33):
            for n in range(1, 17):
                raw, code, _ = write_filler(raw, f"f{n:04}", version, "filler-churn")
                assert code == 0
                record["churnWrites"] += 1
        for n in range(17, 2049):
            old_hash = sha(raw)
            raw, code, capture = write_filler(raw, f"f{n:04}", 0, "filler-physical-full")
            if code == 91:
                record["fillerRefusal"] = dict(attemptedKey=f"f{n:04}", SDKStatus=capture["operationStatus"], flashBytesUnchanged=sha(raw) == old_hash, retainedFillerKeys=len(wanted))
                break
            record["fillerWrites"] += 1
        assert "fillerRefusal" in record, "fixed maximum reached without observing SDK fullness"
        assert record["SDKSectorErases"] > 0, "deliberate churn did not exercise observed SDK GC"
        (args.evidence / f"{order}-artificial-full-baseline.bin").write_bytes(raw)
        (args.evidence / f"{order}-retained-filler.json").write_text(json.dumps(wanted, sort_keys=True) + "\n")

        # Distinct experiment: valid final retirement pending write at artificial
        # fullness. It may be exact old/new/HOLD; no reserve or zero-write promise.
        s = p["snapshots"][127]
        operation = (p["namespace"], f"snap{s['slot']}", s["sealed"])
        new = dict(pre, **{operation[1]: operation[2]})
        allowed = ["exact-pre-final-retirement", "exact-final-retirement-pending"]
        changed, failed, trace, code = views.journals.run(raw, [operation])
        reopened, observed, fillers, _ = views.observe(changed, wanted, allowed, emitter, dict(order=order, phase="journal-at-artificial-full", mode="uncut", sourceReturnCode=code, sourceStatus=failed["operationStatus"], flashBytesUnchanged=sha(changed) == sha(raw)))
        assert fillers == wanted
        assert observed[:7] == [state(f, TERMINAL) for f in profiles[:7]]
        assert all(observed[7].get(k) == v for k, v in pre.items() if k != operation[1])
        assert all(k in new and v in {pre.get(k), new[k]} for k, v in observed[7].items())
        record["journalOperation"] = dict(SDKReturnCode=code, SDKStatus=failed["operationStatus"], flashBytesUnchanged=sha(changed) == sha(raw), storedState=next((label for label in allowed if observed[7] == state(p, label)), "HOLD"), primitiveEvents=len([e for e in trace if "primitive" in e]))
        primitives = [e["primitive"] for e in trace if "primitive" in e]
        first_inventory = next((i for i, e in enumerate(trace) if e.get("call") == "open_readonly"), len(trace))
        logical = [e["logical"] for e in trace[:first_inventory] if "logical" in e and e["status"] == 0]
        cuts = 0
        for mode, points in [("word", primitives), ("logical", logical), ("transient", range(len(primitives) + 1))]:
            for cut in points:
                changed, failed, _, code = views.journals.run(raw, [operation], mode, cut)
                reopened, journals, actual, _ = views.observe(changed, wanted, allowed, emitter, dict(order=order, phase="journal-at-artificial-full", mode=mode, cut=cut, sourceReturnCode=code, sourceStatus=failed.get("operationStatus") if failed else None))
                assert actual == wanted
                assert all(journals[7].get(k) == v for k, v in pre.items() if k != operation[1])
                assert all(k in new and v in {pre.get(k), new[k]} for k, v in journals[7].items())
                cuts += 1
        record["journalCutCases"] = cuts
        summary["orders"].append(record)
        print(record, flush=True)
    emitter.stream.close()
    views.journals.archive.close()
    views.filler.archive.close()
    summary.update(freshJournalProcesses=views.journals.count, freshFillerViewProcesses=views.filler.count, completeObservations=emitter.observations, codecInputRecords=emitter.count, codecInputSHA256=sha((args.evidence / "lifecycle-codec-input.jsonl").read_bytes()))
    (args.evidence / "fullness-campaign.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except ReconstructionHold as hold:
        print(str(hold), flush=True)
        raise SystemExit(92)
