use super::*;
use crate::unmanaged::config::LabelRule;
use crate::unmanaged::pce::Label;
use std::collections::VecDeque;
use std::sync::Mutex;

const NOW: i64 = 1_800_000_000;
const WIN: i64 = 600;
const HOUR: i64 = 3600;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn label(key: &str, value: &str) -> Label {
    Label { href: format!("/orgs/1/labels/{key}-{value}"), key: key.into(), value: value.into() }
}

/// Scripted PCE: `errs` queues errors per method (taken before the default behaviour); every call is recorded.
#[derive(Default)]
struct PceState {
    calls: Vec<String>,
    dims: BTreeSet<String>,
    /// Labels on the PCE; `labels()` returns those not in `unexported`.
    labels: Vec<Label>,
    unexported: BTreeSet<(String, String)>,
    /// `find_label` misses these although `create_label` reports them as existing.
    unresolvable: BTreeSet<(String, String)>,
    /// Workloads in the export, and ones created since (seen only by `has_workload`).
    workloads: BTreeSet<IpAddr>,
    late: BTreeSet<IpAddr>,
    errs: HashMap<&'static str, VecDeque<PceError>>,
    bulk_results: VecDeque<Vec<CreateResult>>,
    created: Vec<NewWorkload>,
}

#[derive(Clone)]
pub(crate) struct FakePce(Arc<Mutex<PceState>>);

impl FakePce {
    pub(crate) fn new() -> Self {
        let st = PceState {
            dims: ["env", "app", "loc"].map(String::from).into(),
            labels: vec![label("env", "prod"), label("loc", "dc1")],
            ..Default::default()
        };
        Self(Arc::new(Mutex::new(st)))
    }
    fn st(&self) -> std::sync::MutexGuard<'_, PceState> {
        self.0.lock().unwrap()
    }
    fn fail(&self, method: &'static str, e: PceError) {
        self.st().errs.entry(method).or_default().push_back(e);
    }
    pub(crate) fn calls(&self, prefix: &str) -> Vec<String> {
        self.st().calls.iter().filter(|c| c.starts_with(prefix)).cloned().collect()
    }
    fn call(&self, c: String, method: &'static str) -> Result<std::sync::MutexGuard<'_, PceState>, PceError> {
        let mut st = self.st();
        st.calls.push(c);
        match st.errs.get_mut(method).and_then(VecDeque::pop_front) {
            Some(e) => Err(e),
            None => Ok(st),
        }
    }
}

impl PceApi for FakePce {
    fn label_dimensions(&self) -> Result<BTreeSet<String>, PceError> {
        Ok(self.call("label_dimensions".into(), "label_dimensions")?.dims.clone())
    }
    fn labels(&self) -> Result<Vec<Label>, PceError> {
        let st = self.call("labels".into(), "labels")?;
        let un = &st.unexported;
        Ok(st.labels.iter().filter(|l| !un.contains(&(l.key.clone(), l.value.clone()))).cloned().collect())
    }
    fn find_label(&self, key: &str, value: &str) -> Result<Option<Label>, PceError> {
        let st = self.call(format!("find_label {key}={value}"), "find_label")?;
        if st.unresolvable.contains(&(key.into(), value.into())) {
            return Ok(None);
        }
        Ok(st.labels.iter().find(|l| l.key == key && l.value == value).cloned())
    }
    fn create_label(&self, key: &str, value: &str) -> Result<Label, PceError> {
        let mut st = self.call(format!("create_label {key}={value}"), "create_label")?;
        if st.labels.iter().any(|l| l.key == key && l.value == value) {
            return Err(PceError::Exists);
        }
        st.labels.push(label(key, value));
        Ok(label(key, value))
    }
    fn workload_ips(&self) -> Result<BTreeSet<IpAddr>, PceError> {
        Ok(self.call("workload_ips".into(), "workload_ips")?.workloads.clone())
    }
    fn has_workload(&self, ip: IpAddr) -> Result<bool, PceError> {
        let st = self.call(format!("has_workload {ip}"), "has_workload")?;
        Ok(st.workloads.contains(&ip) || st.late.contains(&ip))
    }
    fn bulk_create(&self, batch: &[NewWorkload]) -> Result<Vec<CreateResult>, PceError> {
        let mut st = self.call(format!("bulk_create {}", batch.len()), "bulk_create")?;
        let res = st.bulk_results.pop_front().unwrap_or_else(|| vec![CreateResult::Created; batch.len()]);
        st.created.extend(batch.iter().cloned());
        Ok(res)
    }
}

struct FakeDns(HashMap<IpAddr, String>);

impl ReverseDns for FakeDns {
    fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.0.get(&ip).cloned()
    }
}

fn cfg() -> UnmanagedConfig {
    let rule = |c: &str, l: &[(&str, &str)]| LabelRule {
        cidr: c.parse().unwrap(),
        labels: l.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    };
    UnmanagedConfig {
        enabled: true,
        label_rules: vec![
            rule("10.20.0.0/16", &[("env", "prod"), ("loc", "dc1")]),
            rule("10.20.1.0/24", &[("app", "billing")]),
        ],
        ..Default::default()
    }
}

type Logs = Arc<Mutex<Vec<String>>>;

struct Harness {
    eng: Engine<FakePce>,
    pce: FakePce,
    logs: Logs,
    dir: tempfile::TempDir,
}

impl Harness {
    fn new(cfg: UnmanagedConfig) -> Self {
        Self::with_known(cfg, None)
    }
    /// `known`: persisted `uw_known.json` written before the engine starts.
    fn with_known(cfg: UnmanagedConfig, known: Option<KnownState>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        if let Some(k) = known {
            StateFiles::new(dir.path(), "pce", 1).save_known(&k).unwrap();
        }
        let pce = FakePce::new();
        let dns: Arc<dyn ReverseDns> = Arc::new(FakeDns([(ip("10.20.1.1"), "web1.corp.".to_string())].into()));
        let mut eng = Engine::new(cfg, pce.clone(), Some(dns), StateFiles::new(dir.path(), "pce", 1));
        let logs: Logs = Arc::default();
        let sink = logs.clone();
        eng.set_log(Box::new(move |l| sink.lock().unwrap().push(l.to_string())));
        Self { eng, pce, logs, dir }
    }
    fn window(&mut self, n: i64, flows: &[(&str, u64)]) -> Summary {
        self.eng.on_window(&report(flows), NOW + n * WIN)
    }
    fn logged(&self, needle: &str) -> usize {
        self.logs.lock().unwrap().iter().filter(|l| l.contains(needle)).count()
    }
    fn created_ips(&self) -> Vec<IpAddr> {
        self.pce.st().created.iter().map(|w| w.ip).collect()
    }
}

fn report(flows: &[(&str, u64)]) -> WindowReport {
    WindowReport { new_ips: Vec::new(), ip_flow_counts: flows.iter().map(|(a, n)| (a.to_string(), *n)).collect() }
}

fn fresh(ago: i64) -> KnownState {
    KnownState { last_full_refresh: Some(NOW - ago), ..Default::default() }
}

#[test]
fn creates_after_threshold_with_labels_and_hostname() {
    let mut h = Harness::new(cfg());
    h.window(0, &[("10.20.1.1", 6)]);
    assert!(h.pce.calls("bulk_create").is_empty());
    let s = h.window(1, &[("10.20.1.1", 6)]);
    assert_eq!((s.created, s.labels_created, s.resolved, s.looked_up), (1, 1, 1, 1));
    let w = h.pce.st().created[0].clone();
    assert_eq!(w.ip, ip("10.20.1.1"));
    assert_eq!(w.hostname.as_deref(), Some("web1.corp"));
    let hrefs: BTreeSet<_> = w.label_hrefs.into_iter().collect();
    let want: BTreeSet<_> = ["env-prod", "app-billing", "loc-dc1"].map(|l| format!("/orgs/1/labels/{l}")).into();
    assert_eq!(hrefs, want);
    h.window(2, &[("10.20.1.2", 10)]);
    assert_eq!(h.created_ips(), [ip("10.20.1.1"), ip("10.20.1.2")]);
    assert_eq!(h.pce.calls("create_label"), ["create_label app=billing"]);
}

#[test]
fn known_ip_never_created() {
    let mut h = Harness::new(cfg());
    h.pce.st().workloads.insert(ip("10.20.1.1"));
    h.window(0, &[("10.20.1.1", 50)]);
    h.window(1, &[("10.20.1.1", 50)]);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert!(h.pce.calls("has_workload").is_empty());
}

#[test]
fn no_creation_until_first_successful_load() {
    let mut h = Harness::new(cfg());
    h.pce.fail("workload_ips", PceError::Transient("down".into()));
    h.pce.fail("workload_ips", PceError::Transient("down".into()));
    h.window(0, &[("10.20.1.1", 10)]);
    h.window(1, &[("10.20.1.1", 10)]);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert_eq!(h.logged("Unmanaged workloads: workload_ips failed: down"), 2);
    h.window(2, &[]);
    assert_eq!(h.created_ips(), [ip("10.20.1.1")]);
}

#[test]
fn stale_list_pauses_after_double_refresh() {
    let mut h = Harness::new(cfg());
    h.window(0, &[]); // refresh succeeds at NOW
    for _ in 0..2 {
        h.pce.fail("workload_ips", PceError::Transient("down".into()));
    }
    h.eng.on_window(&report(&[("10.20.1.1", 10)]), NOW + 47 * HOUR);
    assert_eq!(h.created_ips(), [ip("10.20.1.1")]);
    h.eng.on_window(&report(&[("10.20.1.2", 10)]), NOW + 49 * HOUR);
    assert_eq!(h.created_ips(), [ip("10.20.1.1")]);
    assert_eq!(h.logged("Unmanaged workloads: creation paused, no workload list newer than 48h"), 1);
}

#[test]
fn persisted_list_older_than_refresh_is_not_trusted_at_startup() {
    // Between 1x and 2x refresh_hours: the grace applies only after a refresh succeeded in this process.
    let mut h = Harness::with_known(cfg(), Some(fresh(30 * HOUR)));
    h.pce.fail("workload_ips", PceError::Transient("down".into()));
    h.window(0, &[("10.20.1.1", 10)]);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert_eq!(h.logged("Unmanaged workloads: creation paused, no workload list newer than 24h"), 1);
}

#[test]
fn future_refresh_stamp_is_not_trusted() {
    let mut h = Harness::with_known(cfg(), Some(fresh(-HOUR)));
    h.pce.fail("workload_ips", PceError::Transient("down".into()));
    h.window(0, &[("10.20.1.1", 10)]);
    assert_eq!(h.pce.calls("workload_ips").len(), 1);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert_eq!(h.logged("Unmanaged workloads: creation paused"), 1);
    // After a successful refresh the same process trusts its own stamp again.
    h.window(1, &[]);
    assert_eq!(h.created_ips(), [ip("10.20.1.1")]);
}

#[test]
fn persisted_fresh_list_skips_startup_export() {
    let mut h = Harness::with_known(cfg(), Some(fresh(HOUR)));
    h.window(0, &[("10.20.1.1", 10)]);
    assert!(h.pce.calls("workload_ips").is_empty());
    assert_eq!(h.created_ips(), [ip("10.20.1.1")]);
}

#[test]
fn precreate_check_drops_new_workload() {
    let mut c = cfg();
    c.max_creates_per_window = 1;
    let mut h = Harness::new(c);
    h.pce.st().late.insert(ip("10.20.1.1"));
    let s = h.window(0, &[("10.20.1.1", 20), ("10.20.1.2", 10)]);
    assert_eq!(h.pce.calls("has_workload"), ["has_workload 10.20.1.1"]);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert_eq!((s.eligible, s.deferred, s.created), (2, 1, 0));
    assert!(h.eng.known.ips.contains(&ip("10.20.1.1")));
    assert!(!h.eng.window.totals().contains_key(&ip("10.20.1.1")));
    h.window(1, &[]);
    assert_eq!(h.created_ips(), [ip("10.20.1.2")]);
}

#[test]
fn precreate_failure_creates_nothing() {
    let mut h = Harness::new(cfg());
    h.pce.fail("has_workload", PceError::Transient("timeout".into()));
    let s = h.window(0, &[("10.20.1.1", 10), ("10.20.1.2", 10)]);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert!(h.pce.calls("create_label").is_empty());
    assert_eq!((s.created, s.errors), (0, 1));
    assert_eq!(h.logged("Unmanaged workloads: has_workload failed: timeout"), 1);
    h.window(1, &[]);
    assert_eq!(h.created_ips(), [ip("10.20.1.1"), ip("10.20.1.2")]);
}

#[test]
fn missing_label_type_disables_with_message() {
    let mut h = Harness::new(cfg());
    h.pce.st().dims.remove("loc");
    h.window(0, &[("10.20.1.1", 10)]);
    h.window(1, &[("10.20.1.1", 10)]);
    assert_eq!(h.pce.st().calls, ["label_dimensions"]);
    assert_eq!(
        *h.logs.lock().unwrap(),
        ["Unmanaged workloads disabled: label rule 10.20.0.0/16 uses label type 'loc', which does not exist on the PCE"]
    );
}

#[test]
fn label_exists_falls_back_to_find_label() {
    let mut h = Harness::new(cfg());
    {
        let mut st = h.pce.st();
        st.labels.push(label("app", "billing"));
        st.unexported.insert(("app".into(), "billing".into()));
    }
    let s = h.window(0, &[("10.20.1.1", 10)]);
    assert_eq!(h.pce.calls("find_label"), ["find_label app=billing"]);
    assert_eq!((s.created, s.labels_created, s.errors), (1, 0, 0));
    assert!(h.pce.st().created[0].label_hrefs.contains(&"/orgs/1/labels/app-billing".to_string()));
    h.window(1, &[("10.20.1.2", 10)]);
    assert_eq!(h.pce.calls("create_label").len(), 1);
}

#[test]
fn unresolvable_label_skips_ips_without_looping() {
    let mut h = Harness::new(cfg());
    {
        let mut st = h.pce.st();
        st.labels.push(label("app", "billing"));
        st.unexported.insert(("app".into(), "billing".into()));
        st.unresolvable.insert(("app".into(), "billing".into()));
    }
    let s = h.window(0, &[("10.20.1.1", 10), ("10.20.1.2", 10), ("10.20.2.1", 10)]);
    assert_eq!(h.pce.calls("create_label").len(), 1);
    assert_eq!(h.created_ips(), [ip("10.20.2.1")]);
    assert_eq!((s.created, s.errors), (1, 1));
    let line = "Unmanaged workloads: label app=billing exists on the PCE but could not be resolved; skipping IPs that need it";
    assert_eq!(h.logged(line), 1);
    h.window(1, &[]);
    assert_eq!(h.pce.calls("create_label").len(), 2);
    assert_eq!(h.logged(line), 2);
}

#[test]
fn partial_bulk_failure_marks_only_created_and_duplicates() {
    let flows = [("10.20.1.1", 30), ("10.20.1.2", 20), ("10.20.1.3", 10)];
    let mut h = Harness::new(cfg());
    h.pce.st().bulk_results.push_back(vec![
        CreateResult::Created,
        CreateResult::AlreadyExists,
        CreateResult::Failed("bad".into()),
    ]);
    let s = h.window(0, &flows);
    assert_eq!((s.created, s.errors), (1, 1));
    assert_eq!(h.eng.known.ips, BTreeSet::from([ip("10.20.1.1"), ip("10.20.1.2")]));
    assert_eq!(h.eng.known.created_at.len(), 1);
    assert_eq!(h.eng.window.totals().keys().copied().collect::<Vec<_>>(), [ip("10.20.1.3")]);
    assert_eq!(h.logged("Unmanaged workloads: bulk_create failed for 10.20.1.3: bad"), 1);

    let mut h = Harness::new(cfg());
    h.pce.fail("bulk_create", PceError::Transient("503".into()));
    let s = h.window(0, &flows);
    assert_eq!((s.created, s.errors), (0, 1));
    // Nothing becomes known; the ambiguous failure is still charged to the daily cap.
    assert!(h.eng.known.ips.is_empty());
    assert_eq!(h.eng.known.created_at.len(), 3);
    assert_eq!(h.eng.window.totals().len(), 3);
}

#[test]
fn ambiguous_bulk_failure_charges_daily_cap() {
    let mut c = cfg();
    (c.max_creates_per_day, c.max_creates_per_window) = (3, 2);
    let mut h = Harness::new(c.clone());
    h.pce.fail("bulk_create", PceError::Transient("timeout".into()));
    h.window(0, &[("10.20.1.1", 30), ("10.20.1.2", 20), ("10.20.1.3", 10)]);
    assert!(h.eng.known.ips.is_empty());
    assert_eq!((h.eng.known.created_at.len(), h.eng.window.totals().len()), (2, 3));
    h.window(1, &[]);
    assert_eq!(h.pce.calls("bulk_create"), ["bulk_create 2", "bulk_create 1"]);

    // A clean refusal created nothing, so it is not charged.
    let mut h = Harness::new(c);
    h.pce.fail("bulk_create", PceError::Auth(403));
    h.window(0, &[("10.20.1.1", 30)]);
    assert!(h.eng.known.created_at.is_empty());
}

#[test]
fn create_saves_known_right_after_bulk_create() {
    let w = |a: &str| NewWorkload {
        ip: ip(a),
        hostname: None,
        label_hrefs: Vec::new(),
        external_data_set: "flowpilot".into(),
    };
    let on_disk = |h: &Harness| StateFiles::new(h.dir.path(), "pce", 1).load_known();
    let mut h = Harness::new(cfg());
    h.eng.create(&[w("10.20.1.1")], &mut Summary::default(), NOW);
    let k = on_disk(&h);
    assert_eq!((k.ips, k.created_at), (BTreeSet::from([ip("10.20.1.1")]), vec![NOW]));

    // An ambiguous failure's charge is saved as well.
    let mut h = Harness::new(cfg());
    h.pce.fail("bulk_create", PceError::Transient("timeout".into()));
    h.eng.create(&[w("10.20.1.1"), w("10.20.1.2")], &mut Summary::default(), NOW);
    assert_eq!(on_disk(&h).created_at, [NOW, NOW]);
}

#[test]
fn failed_ledger_save_stops_further_chunks() {
    let mut h = Harness::new(cfg());
    // A directory where the temp file goes makes every save of the known set fail.
    std::fs::create_dir(h.dir.path().join("pce-org1-uw_known.json.tmp")).unwrap();
    let batch: Vec<NewWorkload> = (0..1001u32)
        .map(|i| NewWorkload {
            ip: IpAddr::from(std::net::Ipv4Addr::from(0x0a14_0000 + i)),
            hostname: None,
            label_hrefs: Vec::new(),
            external_data_set: "flowpilot".into(),
        })
        .collect();
    let mut sum = Summary::default();
    h.eng.create(&batch, &mut sum, NOW);
    assert_eq!(h.pce.calls("bulk_create"), ["bulk_create 1000"]);
    assert_eq!(h.logged("Unmanaged workloads: saving the known workloads failed"), 1);
}

#[test]
fn dry_run_writes_nothing_and_logs() {
    let mut c = cfg();
    c.dry_run = true;
    let mut h = Harness::new(c);
    let s = h.window(0, &[("10.20.1.1", 10), ("10.20.2.1", 10)]);
    assert!(h.pce.calls("create_label").is_empty() && h.pce.calls("bulk_create").is_empty());
    assert!(s.to_string().starts_with("Unmanaged workloads (dry run):"));
    assert_eq!(h.logged("Unmanaged workloads (dry run): would create label app=billing"), 1);
    let new_label = "Unmanaged workloads (dry run): would create workload 10.20.1.1 hostname=web1.corp \
                     labels=app=billing,env=prod,loc=dc1";
    assert_eq!(h.logged(new_label), 1);
    let line = "Unmanaged workloads (dry run): would create workload 10.20.2.1 hostname=- labels=env=prod,loc=dc1";
    assert_eq!(h.logged(line), 1);
    h.window(1, &[]);
    assert_eq!((h.logged(new_label), h.logged(line)), (2, 2));
    assert!(h.eng.known.ips.is_empty());
}

#[test]
fn auth_error_message() {
    let mut h = Harness::new(cfg());
    h.pce.fail("bulk_create", PceError::Auth(403));
    h.window(0, &[("10.20.1.1", 10)]);
    let line = "Unmanaged workloads: PCE refused bulk_create with HTTP 403; the API key needs permission to create workloads";
    assert_eq!(h.logged(line), 1);
}

#[test]
fn daily_cap_warning_logged_once() {
    let mut c = cfg();
    c.max_creates_per_day = 1;
    let mut h = Harness::with_known(c, Some(KnownState { created_at: vec![NOW - HOUR], ..fresh(HOUR) }));
    h.window(0, &[("10.20.1.1", 10)]);
    h.window(1, &[]);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert_eq!(h.logged("Unmanaged workloads: daily cap of 1 reached, creation resumes as the 24h window frees up"), 1);
}

#[test]
fn burst_pauses_only_the_crossing_window() {
    let mut c = cfg();
    (c.max_creates_per_day, c.max_creates_per_window) = (3, 2);
    let mut h = Harness::new(c);
    // One IP already near the threshold, so its crossing next window is not part of the burst.
    h.window(0, &[("10.20.2.9", 5)]);
    let burst = [("10.20.2.1", 10), ("10.20.2.2", 10), ("10.20.2.3", 10), ("10.20.2.4", 10)];
    let s = h.window(1, &burst);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert_eq!(s.eligible, 4);
    let line = "Unmanaged workloads: burst pause, 4 IPs became eligible in one window (more than max_creates_per_day 3) \
                in 10.0.0.0/8; check networks/exclude_networks";
    assert_eq!(h.logged(line), 1);
    // No new crossings beyond the cap: the backlog drains through the caps.
    let s = h.window(2, &[("10.20.2.9", 5)]);
    assert_eq!((s.eligible, s.created, s.deferred), (5, 2, 3));
    assert_eq!(h.logged("burst pause"), 1);
    h.window(3, &[]);
    assert_eq!(h.created_ips().len(), 3);
}

#[test]
fn crossings_while_paused_still_trigger_burst() {
    let mut c = cfg();
    (c.max_creates_per_day, c.max_creates_per_window) = (3, 2);
    let mut h = Harness::new(c);
    h.pce.fail("workload_ips", PceError::Auth(403));
    h.window(0, &[("10.20.2.1", 10), ("10.20.2.2", 10), ("10.20.2.3", 10), ("10.20.2.4", 10)]);
    assert_eq!(h.logged("creation paused"), 1);
    // The load works now; no new crossings, but the paused window's crossings are still checked.
    h.window(1, &[]);
    assert!(h.pce.calls("bulk_create").is_empty());
    assert_eq!(h.logged("Unmanaged workloads: burst pause, 4 IPs became eligible in one window"), 1);
    // Checked once: the next window drains the backlog through the caps.
    h.window(2, &[]);
    assert_eq!(h.created_ips().len(), 2);
}

#[test]
fn shutdown_counts_but_never_creates() {
    let mut h = Harness::new(cfg());
    h.eng.on_shutdown(&report(&[("10.20.1.1", 20), ("8.8.8.8", 5)]), NOW);
    assert!(h.pce.st().calls.is_empty());
    let saved = StateFiles::new(h.dir.path(), "pce", 1).load_window().totals();
    assert_eq!(saved, HashMap::from([(ip("10.20.1.1"), 20)]));
}

#[test]
fn summary_format_exact() {
    let mut s = Summary {
        candidates: 37,
        eligible: 4,
        created: 4,
        deferred: 0,
        resolved: 3,
        looked_up: 4,
        labels_created: 1,
        errors: 0,
        dry_run: false,
    };
    assert_eq!(
        s.to_string(),
        "Unmanaged workloads: 37 candidates, 4 eligible, 4 created, 0 deferred, 3/4 resolved, 1 label created, 0 errors"
    );
    s.labels_created = 2;
    s.dry_run = true;
    assert_eq!(
        s.to_string(),
        "Unmanaged workloads (dry run): 37 candidates, 4 eligible, 4 created, 0 deferred, 3/4 resolved, 2 labels created, 0 errors"
    );
}

fn at(n: i64) -> Option<std::time::SystemTime> {
    Some(std::time::UNIX_EPOCH + Duration::from_secs((NOW + n * WIN) as u64))
}

impl Harness {
    fn stats(&self) -> crate::stats::UnmanagedStats {
        self.eng.stats().lock().unwrap().clone()
    }
}

#[test]
fn stats_after_capped_window() {
    let mut c = cfg();
    (c.max_creates_per_window, c.max_creates_per_day) = (2, 50);
    let mut h = Harness::new(c);
    let s0 = h.stats();
    assert_eq!((s0.dry_run, s0.daily_cap, s0.per_window_cap), (false, 50, 2));
    assert_eq!((s0.last_refresh_at, s0.last_refresh_ok), (None, None));
    h.pce.st().workloads.insert(ip("10.9.9.9"));
    h.window(0, &[("10.20.1.1", 30), ("10.20.2.1", 20), ("10.20.2.2", 10), ("10.20.2.3", 1)]);
    let s = h.stats();
    let lw = &s.last_window;
    assert_eq!((lw.candidates, lw.eligible, lw.created, lw.deferred, lw.errors, lw.labels_created), (4, 3, 2, 1, 0, 1));
    assert_eq!((s.created_total, s.created_today, s.deferred_total, s.failed_total), (2, 2, 1, 0));
    assert_eq!((s.would_create_total, s.known_ips), (0, 3));
    assert_eq!((s.last_refresh_at, s.last_refresh_ok), (at(0), Some(true)));
    assert_eq!((s.burst_paused_since, s.disabled_reason.as_deref()), (None, None));
    // The next window creates the deferred one; totals add up.
    h.window(1, &[]);
    let s = h.stats();
    assert_eq!((s.last_window.created, s.last_window.deferred), (1, 0));
    assert_eq!((s.created_total, s.created_today, s.deferred_total), (3, 3, 1));
}

#[test]
fn stats_record_failed_refresh_and_errors() {
    let mut h = Harness::new(cfg());
    h.pce.fail("workload_ips", PceError::Transient("timeout".into()));
    h.window(0, &[("10.20.1.1", 30)]);
    let s = h.stats();
    assert_eq!((s.last_refresh_at, s.last_refresh_ok), (at(0), Some(false)));
    assert_eq!((s.last_window.errors, s.failed_total, s.created_total), (1, 1, 0));
    h.window(1, &[]);
    let s = h.stats();
    assert_eq!((s.last_refresh_at, s.last_refresh_ok, s.created_total), (at(1), Some(true), 1));
}

#[test]
fn stats_seed_refresh_from_persisted_list() {
    let h = Harness::with_known(cfg(), Some(KnownState { ips: [ip("10.1.1.1")].into(), ..fresh(HOUR) }));
    let s = h.stats();
    let t = Some(std::time::UNIX_EPOCH + Duration::from_secs((NOW - HOUR) as u64));
    assert_eq!((s.known_ips, s.last_refresh_at, s.last_refresh_ok), (1, t, Some(true)));
}

#[test]
fn stats_burst_pause_since_and_end() {
    let mut c = cfg();
    (c.max_creates_per_day, c.max_creates_per_window) = (3, 2);
    let mut h = Harness::new(c);
    h.window(0, &[]);
    h.window(1, &[("10.20.2.1", 10), ("10.20.2.2", 10), ("10.20.2.3", 10), ("10.20.2.4", 10)]);
    assert_eq!(h.stats().burst_paused_since, at(1));
    h.window(2, &[]);
    let s = h.stats();
    assert_eq!((s.burst_paused_since, s.last_window.created), (None, 2));
}

#[test]
fn stats_dry_run_counts_would_create() {
    let mut c = cfg();
    c.dry_run = true;
    let mut h = Harness::new(c);
    h.window(0, &[("10.20.1.1", 10), ("10.20.2.1", 10)]);
    h.window(1, &[]);
    let s = h.stats();
    assert!(s.dry_run);
    assert_eq!((s.would_create_total, s.created_total, s.created_today, s.last_window.created), (4, 0, 0, 0));
}

#[test]
fn stats_disabled_reason() {
    let mut h = Harness::new(cfg());
    h.pce.st().dims.remove("app");
    h.window(0, &[("10.20.1.1", 10)]);
    let reason = h.stats().disabled_reason.unwrap();
    assert!(reason.starts_with("Unmanaged workloads disabled: label rule 10.20.1.0/24 uses label type 'app'"), "{reason}");
}
