#!/usr/bin/env python3
# Generate synthetic AssayRun records for gate verification.
# Usage: gen_testdata.py <outdir>
import json, random, os, math, sys
random.seed(11)
outdir = sys.argv[1] if len(sys.argv) > 1 else "testdata"
os.makedirs(outdir, exist_ok=True)

def hist_from_samples(samples):
    slots=[0]*40; s=0.0
    for v in samples:
        v=max(1.0,v); i=min(39,int(math.log2(v))); slots[i]+=1; s+=v
    return slots, s, len(samples)

def samples(mean_ns, n=2000, spread=0.15):
    return [random.lognormvariate(math.log(mean_ns), spread) for _ in range(n)]

def run(target_mean, tenancy="single_tenant", cell="c1", cost_frac=0.004, over=False,
        overflow=False, run_var=0.02, name="kvm.exit_handling_latency:HLT", source="kvm_exit"):
    rm = target_mean * (1.0 + random.gauss(0, run_var))
    slots, s, c = hist_from_samples(samples(rm))
    return {
      "schema_version":"0.1.0","run_id":"01J"+"".join(random.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(23)),
      "grade":"reproducible",
      "identity":{"target_adapter":"firecracker","target_adapter_version":"0.3.0","workload_driver":"fio",
                  "workload_driver_version":"0.1.0","sut_git_sha":"abc1234","params":{"vcpu":2},
                  "params_hash":cell,"benchmark_def_sha":"def5678"},
      "fingerprint":{"hostname":"lab","kernel_version":"6.11.0","os_release":"Ubuntu 26.04","cpu_model":"Ryzen",
                     "cpu_count_logical":16,"cpu_count_physical":8,"smt_enabled":False,"cpu_governor":"performance",
                     "thp_setting":"never","total_memory_bytes":137438953472,"kvm_present":True,"tenancy":tenancy,
                     "tuning_requested":{"g":"performance"},"tuning_readback":{"g":"performance"},
                     "numa_topology":{},"pinning_layout":{},"mitigations":{},"microcode_version":"x","nested_virt":False},
      "series":[{"name":name,"unit":"ns","kind":"histogram","source":source,
                 "cardinality":{"class":"singleton"},"cardinality_overflow":overflow,
                 "data":{"layout":"log2","buckets":slots,"sum":s,"count":c}}],
      "self_metrics":[{"probe_id":source,"attach_kind":"tracepoint","run_time_ns":int(cost_frac*3e10),
                       "run_cnt":c,"mean_ns":cost_frac*3e10/c,"steady_cpu_fraction":cost_frac,
                       "over_budget":over,"hot_path":True}],
      "capture_meta":{"gadget":"assayist-capture-kvm","window_ns":30000000000,"cardinality_overflow":overflow}
    }

def w(n,r):
    with open(os.path.join(outdir,f"{n}.json"),"w") as f: json.dump(r,f)

N=10
for i in range(N): w(f"a{i}", run(1000.0))
for i in range(N): w(f"breg{i}", run(1400.0))              # +40% -> FAIL
for i in range(N): w(f"bsame{i}", run(1000.0))             # -> PASS
for i in range(N): w(f"bcont{i}", run(1400.0, over=True))  # -> CONTAMINATED
w("btenancy", run(1000.0, tenancy="density"))              # -> ERROR
for i in range(N): w(f"dbase{i}", run(40_000_000.0, name="restore.resume_to_steady", source="restore"))
for i,ms in enumerate([41,54,69,87,104,124]):
    w(f"dcand{i}", run(ms*1_000_000.0, name="restore.resume_to_steady", source="restore"))
print(f"wrote {len(os.listdir(outdir))} files to {outdir}")
