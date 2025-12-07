use super::dkg::*;
use super::structs::*;
use crate::drand::schemes::*;
use crate::kyber::poly::*;
use crate::kyber::tbls;
use crate::points::KeyPoint;
use crate::traits::*;

use rand::seq::SliceRandom;
use rand::*;
use std::ops::IndexMut;

fn get_nonce() -> [u8; 32] {
    rand::Rng::gen(&mut rand::thread_rng())
}

impl<S: Scheme> Default for Config<S> {
    fn default() -> Self {
        Self {
            long_term: S::Scalar::zero(),
            old_nodes: vec![],
            public_coeffs: vec![],
            new_nodes: vec![],
            share: None,
            threshold: 0,
            old_threshold: 0,
            nonce: [0; 32],
            log: slog::Logger::root(slog::Discard, slog::o!()),
        }
    }
}

#[derive(Clone)]
struct TestNode<S: Scheme> {
    index: u32,
    private: S::Scalar,
    public: KeyPoint<S>,
    dkg: Option<DistKeyGenerator<S>>,
    res: Option<DkgOutput<S>>,
}

impl<S: Scheme> TestNode<S> {
    fn new(index: u32) -> Self {
        let private = S::Scalar::random();
        let public = S::sk_to_pk(&private);

        Self {
            index,
            private,
            public,
            dkg: None,
            res: None,
        }
    }

    fn dkg(&mut self) -> &mut DistKeyGenerator<S> {
        self.dkg.as_mut().unwrap()
    }
}

fn generate_test_nodes<S: Scheme>(n: u32) -> Vec<TestNode<S>> {
    (0..n).map(TestNode::new).collect()
}

fn setup_nodes<S: Scheme>(nodes: &mut [TestNode<S>], c: Config<S>) {
    let nonce = get_nonce();
    for n in nodes.iter_mut() {
        // Clone and modify config for each node.
        let mut node_c = c.clone();
        node_c.long_term = n.private.clone();
        node_c.nonce = nonce;
        n.dkg = Some(DistKeyGenerator::new(node_c).unwrap())
    }
}

fn setup_reshare_nodes<S: Scheme>(nodes: &mut [TestNode<S>], c: Config<S>, coeffs: &[KeyPoint<S>]) {
    let nonce = get_nonce();
    for n in nodes {
        // Clone and modify config for each node.
        let mut c2 = c.clone();
        c2.long_term = n.private.clone();
        c2.nonce = nonce;
        match &n.res {
            Some(res) => c2.share = Some(res.key.clone()),
            None => c2.public_coeffs = coeffs.to_vec(),
        }
        n.dkg = Some(DistKeyGenerator::new(c2).unwrap())
    }
}

fn is_dealer_included(bundles: &[ResponseBundle], dealer: u32) -> bool {
    for bundle in bundles {
        for resp in &bundle.responses {
            if resp.dealer_index == dealer {
                return true;
            }
        }
    }

    false
}

fn nodes_from_test<S: Scheme>(tns: &[TestNode<S>]) -> Vec<Node<S>> {
    tns.iter()
        .map(|tn| Node {
            index: tn.index,
            public: tn.public.clone(),
        })
        .collect()
}

fn public_equal<S: Scheme>(r: &DkgOutput<S>, r2: &DkgOutput<S>) -> bool {
    r.key.commits == r2.key.commits && r.qual == r2.qual
}

fn test_results<S: Scheme>(thr: u32, results: &[DkgOutput<S>]) {
    // Check if all results are consistent.
    for (i, res) in results.iter().enumerate() {
        assert_eq!(thr, res.key.commitments().len() as u32);
        for (j, res2) in results.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(public_equal(res, res2))
        }
    }

    // Checks:
    // - re-creating secret key gives the same public key.
    // - shares are public polynomial evaluation.
    let mut shares: Vec<PriShare<S>> = results
        .iter()
        .map(|res| res.key.pri_share.clone())
        .collect();

    let exp: PubPoly<S> = PubPoly {
        commits: results[0].key.commitments().to_vec(),
    };
    for share in &shares {
        let pub_share = exp.eval(share.index());
        let exp_share = S::sk_to_pk(share.value());
        assert!(pub_share.v == exp_share);
    }
    let secret_poly = recover_pri_poly(&mut shares, thr as usize).unwrap();
    let got_pub = secret_poly.commit();
    assert!(exp == got_pub);

    let secret = recover_secret(&mut shares, thr as usize).unwrap();
    let public = S::sk_to_pk(&secret);
    let exp_key = results[0].key.public();
    assert!(public == *exp_key)
}

type MapDeal<S> = Option<fn(deals: &mut Vec<DealBundle<S>>)>;
type MapResponse = Option<fn(resp: &mut [ResponseBundle])>;
type MapJustif<S> = Option<fn(justs: &mut [JustificationBundle<S>])>;

fn run_dkg<S: Scheme>(
    tns: &mut [TestNode<S>],
    conf: Config<S>,
    dm: MapDeal<S>,
    rm: MapResponse,
    jm: MapJustif<S>,
) -> Vec<DkgOutput<S>> {
    setup_nodes(tns, conf);
    let mut deals: Vec<DealBundle<S>> = vec![];

    for node in tns.iter_mut() {
        let d = node.dkg().deals().unwrap();
        deals.push(d);
    }

    if let Some(dm) = dm {
        dm(&mut deals)
    }

    let mut resp_bundles: Vec<ResponseBundle> = vec![];
    for node in tns.iter_mut() {
        let resp = node.dkg().process_deals(deals.clone()).unwrap();
        resp_bundles.push(resp)
    }

    if let Some(rm) = rm {
        rm(&mut resp_bundles)
    }

    let mut justifs: Vec<JustificationBundle<S>> = Vec::with_capacity(tns.len());
    let mut results: Vec<DkgOutput<S>> = Vec::with_capacity(tns.len());

    for node in tns.iter_mut() {
        match node.dkg().process_responses(&resp_bundles) {
            Ok(Flow::Output(res)) => results.push(res),
            Ok(Flow::Justif(just)) => justifs.push(just),
            // No action while waiting.
            Ok(Flow::WaitingForJustif) => {}
            // Ignoring eviction case.
            Err(DkgError::Evicted) => {}
            Err(e) => panic!("process_responses: index {}, err {e}", node.index),
        }
    }

    if let Some(jm) = jm {
        jm(&mut justifs)
    }

    for node in tns {
        if node.dkg().state == Phase::Finish {
            continue;
        }
        match node.dkg().process_justifications(&justifs) {
            Ok(res) => results.push(res),
            // Ignoring eviction case
            Err(DkgError::Evicted) => {}
            Err(e) => panic!("process_justifications: index {}, err {e}", node.index),
        };
    }

    results
}

/// This tests makes a dealer being evicted and checks if the dealer knows
/// about the eviction itself and quits the DKG.
fn test_self_eviction_dealer<S: Scheme>() {
    let n = 5;
    let thr = 3;
    let mut tns = generate_test_nodes::<S>(n);

    let skipped_index = rand::thread_rng().gen_range(0..n) as usize;
    let new_index = 53;
    tns[skipped_index].index = new_index;

    let list = nodes_from_test(&tns);
    let dealer_to_evict = list[0].index;
    let conf = Config {
        new_nodes: list,
        threshold: thr,
        ..Default::default()
    };
    setup_nodes(&mut tns, conf);

    let mut deals: Vec<DealBundle<S>> = vec![];
    for node in &mut tns {
        let d = node.dkg().deals().unwrap();
        // Simulate that this node doesn't send its deal.
        if node.index == dealer_to_evict {
            continue;
        }
        deals.push(d)
    }

    let mut resp_bundles: Vec<ResponseBundle> = vec![];
    for node in &mut tns {
        let resp = node.dkg().process_deals(deals.clone()).unwrap();
        resp_bundles.push(resp)
    }

    for node in tns.iter_mut() {
        let result = node.dkg().process_responses(&resp_bundles);
        if node.index == dealer_to_evict {
            // Evicting ourselves here so we should stop doing the DKG
            assert!(result.is_err());
            continue;
        }

        assert!(result.is_ok());
        assert!(node.dkg().evicted.iter().any(|i| *i == dealer_to_evict))
    }
}

// This test is running DKG and resharing with skipped indices given there is no
// guarantees that the indices of the nodes are going to be sequentials.
fn test_dkg_skip_index<S: Scheme>() {
    let n = 5;
    let thr = 4;
    let mut tns = generate_test_nodes::<S>(n);

    let skipped_index = 1;
    let new_index = 53;
    tns[skipped_index].index = new_index;
    let list = nodes_from_test(&tns);
    let conf = Config {
        new_nodes: list.clone(),
        threshold: thr,
        ..Default::default()
    };

    let results = run_dkg(&mut tns, conf, None, None, None);
    test_results(thr, &results);

    for (i, t) in &mut tns.iter_mut().enumerate() {
        t.res = Some(results[i].clone())
    }
    test_results(thr, &results);

    // Setup second group with higher node count and higher threshold
    // and remove one node from the previous group.
    let nodes_to_add = 5;
    // Remove one old node.
    let new_n = n - 1 + nodes_to_add;
    // Set the threshold to accept one offline new node.
    let new_t = thr + nodes_to_add - 1;
    let mut new_tns: Vec<TestNode<S>> = Vec::with_capacity(new_n as usize);
    // Remove a random node from the previous group.
    // Note: index 1 is already skipped.
    let tns_idx = tns.iter().map(|n| n.index).collect::<Vec<u32>>();
    let offline_to_remove = *tns_idx.choose(&mut thread_rng()).unwrap();

    for node in &tns {
        if node.index == offline_to_remove {
            continue;
        }
        new_tns.push(node.to_owned());
    }

    // Also mess up with indexing.
    let new_skipped = 2;
    for i in 0..=nodes_to_add {
        // Gonna get filled up at last iteration.
        if i == new_skipped {
            continue;
        }
        // Start at n to be sure we dont overlap with previous indices.
        new_tns.push(TestNode::new(n + i));
    }
    let new_list = nodes_from_test(&mut new_tns);
    let new_conf = Config {
        new_nodes: new_list,
        old_nodes: list,
        threshold: new_t,
        old_threshold: thr,
        ..Default::default()
    };
    setup_reshare_nodes(
        &mut new_tns,
        new_conf,
        &tns[0].res.as_ref().unwrap().key.commits,
    );

    let mut deals: Vec<DealBundle<S>> = vec![];
    for node in new_tns.iter_mut() {
        // New members don't issue deals
        if node.res.is_none() {
            continue;
        }
        let d = node.dkg().deals().unwrap();
        deals.push(d)
    }

    let mut responses: Vec<ResponseBundle> = vec![];
    for node in new_tns.iter_mut() {
        let resp = node.dkg().process_deals(deals.clone()).unwrap();
        // Node from the old group is not present
        // so there should be some responses.
        responses.push(resp)
    }
    // All nodes in the new group should have reported an error
    assert!(new_n == responses.len() as u32);

    let mut results = vec![];
    for node in new_tns.iter_mut() {
        // We should have enough old nodes available to get a successful DKG.
        match node.dkg().process_responses(&mut responses) {
            // Since the last old node is absent he can't give any justifications.
            Ok(Flow::Output(..) | Flow::Justif(..)) => panic!(),
            Ok(Flow::WaitingForJustif) => {}
            Err(_) => panic!(),
        }
    }

    for node in new_tns.iter_mut() {
        let j = vec![];
        match node.dkg().process_justifications(&j) {
            Ok(res) => results.push(res),
            _ => panic!(),
        }
    }
    test_results(new_t, &results)
}

fn test_dkg_full_fast<S: Scheme>() {
    let n = 5;
    let thr = n;
    let mut tns = generate_test_nodes::<S>(n);
    let conf = Config {
        new_nodes: nodes_from_test(&tns),
        threshold: thr,
        ..Default::default()
    };

    let results = run_dkg(&mut tns, conf, None, None, None);
    test_results(thr, &results);
}

fn test_self_eviction_share_holder<S: Scheme>() {
    let n = 5;
    let thr = 4;

    let mut tns = generate_test_nodes::<S>(n);
    let list = nodes_from_test(&tns);
    let conf = Config {
        new_nodes: list.clone(),
        threshold: thr,
        ..Default::default()
    };

    let results = run_dkg(&mut tns, conf, None, None, None);
    for (i, t) in tns.iter_mut().enumerate() {
        t.res = Some(results[i].clone())
    }
    test_results(thr, &results);

    // Create a partial signature with the share now and make sure the partial
    // signature is verifiable and then *not* verifiable after the resharing.
    let old_share = &results[0].key.pri_share;
    let msg = "Hello World".as_bytes();
    let old_partial = tbls::sign(old_share, msg).unwrap();
    let poly = PubPoly {
        commits: results[0].key.commits.clone(),
    };
    tbls::verify(&poly, msg, &old_partial).expect("invalid signature");

    // Setup second group with higher node count and higher threshold
    // and remove one node from the previous group.
    let new_n = n + 5;
    let new_t = thr + 4;
    let mut new_tns = tns.clone();
    let new_node = new_n - n;
    for i in 0..new_node {
        new_tns.push(TestNode::new(n + 1 + i))
    }
    let new_index_to_evict = new_tns[new_tns.len() - 1].index;
    let new_list = nodes_from_test(&new_tns);
    let new_conf = Config {
        new_nodes: new_list,
        old_nodes: list,
        threshold: new_t,
        old_threshold: thr,
        ..Default::default()
    };

    setup_reshare_nodes(
        &mut new_tns,
        new_conf,
        &tns[0].res.as_ref().unwrap().key.commits,
    );

    let mut deals: Vec<DealBundle<S>> = vec![];
    for node in new_tns.iter_mut() {
        // New members don't issue deals
        if node.res.is_none() {
            continue;
        }
        deals.push(node.dkg().deals().unwrap())
    }

    let mut responses: Vec<ResponseBundle> = vec![];
    for node in &mut new_tns {
        let mut resp = node.dkg().process_deals(deals.clone()).unwrap();

        if node.index == new_index_to_evict {
            // Insert a bad session ID so this new recipient should be evicted
            resp.session_id = "That looks so wrong".as_bytes().into();
        }
        responses.push(resp)
    }
    assert!(!responses.is_empty());

    for node in new_tns.iter_mut() {
        let res = node.dkg().process_responses(&responses);
        assert!(node.dkg().evicted_holders.contains(&new_index_to_evict));
        if node.index == new_index_to_evict {
            assert!(res.is_err());
            continue;
        }
        assert!(res.is_ok())
    }
}

fn test_dkg_resharing<S: Scheme>() {
    let n = 5;
    let thr = 4;
    let mut tns = generate_test_nodes(n);
    let list = nodes_from_test(&tns);
    let conf = Config {
        new_nodes: list.clone(),
        threshold: thr,
        ..Default::default()
    };

    let results = run_dkg(&mut tns, conf, None, None, None);
    for (i, t) in tns.iter_mut().enumerate() {
        t.res = Some(results[i].clone())
    }
    test_results(thr, &results);

    // Create a partial signature with the share now and make sure the partial
    // signature is verifiable and then *not* verifiable after the resharing.
    let old_share = &results[0].key.pri_share;
    let msg = "Hello World".as_bytes();
    let old_partial = tbls::sign(old_share, msg).unwrap();
    let poly = PubPoly {
        commits: results[0].key.commits.clone(),
    };
    tbls::verify(&poly, msg, &old_partial).expect("invalid signature");

    // Setup second group with higher node count and higher threshold
    // and remove one node from the previous group.
    let new_n = n + 5;
    let new_t = thr + 4;
    // Remove the last node from the previous group.
    let mut new_tns = tns.get(..tns.len() - 1).unwrap().to_vec();
    let offline = 1;
    // + offline because we fill the gap of the offline nodes by new nodes.
    let new_node = new_n - n + offline;
    for i in 0..new_node {
        // New node can have the same index as a previous one, separation is made.
        new_tns.push(TestNode::new(n - 1 + i));
    }
    let new_list = nodes_from_test(&new_tns);
    let new_conf = Config {
        new_nodes: new_list,
        old_nodes: list,
        threshold: new_t,
        old_threshold: thr,
        ..Default::default()
    };

    setup_reshare_nodes(
        &mut new_tns,
        new_conf,
        &tns[0].res.as_ref().unwrap().key.commits,
    );

    let mut deals: Vec<DealBundle<S>> = vec![];
    for node in new_tns.iter_mut() {
        // New members don't issue deals.
        if node.res.is_none() {
            continue;
        }
        deals.push(node.dkg().deals().unwrap())
    }

    // Last node from the old group is not present so there should be some responses.
    let mut responses: Vec<ResponseBundle> = vec![];
    for node in new_tns.iter_mut() {
        let resp = node.dkg().process_deals(deals.clone()).unwrap();
        responses.push(resp)
    }
    assert!(!responses.is_empty());

    // Since the last old node is absent he can't give any justifications.
    let mut results = vec![];
    for node in new_tns.iter_mut() {
        match node.dkg().process_responses(&responses) {
            Ok(Flow::Output(..) | Flow::Justif(..)) => panic!(),
            Ok(Flow::WaitingForJustif) => {}
            Err(_) => panic!(),
        }
    }

    for node in new_tns.iter_mut() {
        match node.dkg().process_justifications(&[]) {
            Ok(res) => results.push(res),
            _ => panic!(),
        }
    }
    test_results(new_t, &results);

    // Check if tbls signature is correct.
    let new_share = &results[0].key.pri_share;
    let new_partial = tbls::sign(new_share, msg).unwrap();
    let new_poly = PubPoly {
        commits: results[0].key.commits.clone(),
    };
    tbls::verify(&new_poly, msg, &new_partial).expect("invalid signature");

    // Assert that old partial cannot be verified with the new public polynomial.
    assert!(tbls::verify(&poly, msg, &new_partial).is_err())
}

fn test_dkg_threshold<S: Scheme>() {
    let n = 5;
    let thr = 4;
    let mut tns = generate_test_nodes::<S>(n);
    let list = nodes_from_test(&tns);
    let conf = Config {
        new_nodes: list,
        threshold: thr,
        ..Default::default()
    };

    fn dm<S: Scheme>(deals: &mut Vec<DealBundle<S>>) {
        // Make first dealer absent.
        deals.remove(0);

        // Make the second dealer creating a invalid share for 3rd participant.
        deals.index_mut(0).deals[2].encrypted_share =
            "Another one bites the dust".as_bytes().to_vec();
    }

    fn rm(resp: &mut [ResponseBundle]) {
        // Must be at least a complaint about node 0.
        assert!(is_dealer_included(resp, 0));
        // If we are checking responses from node 2, then it must also
        // include a complaint for node 1.
        assert!(is_dealer_included(resp, 1))
    }

    fn jm<S: Scheme>(justs: &mut [JustificationBundle<S>]) {
        // Note: do not inspect justifications from evicted node (index 0)
        // because this flow is never used in practice.
        assert!(justs.iter().any(|bundle| bundle.dealer_index == 1))
    }

    let results = run_dkg(&mut tns, conf, Some(dm), Some(rm), Some(jm));
    let mut filtered = vec![];
    for n in tns.iter_mut() {
        if n.index == 0 {
            // Node 0 is excluded by all others since he didn't even provide a
            // deal at the first phase,i.e. it didn't even provide a public
            // polynomial at the first phase.
            continue;
        }
        for res in &results {
            if res.key.pri_share.index() != n.index {
                continue;
            }
            for node_qual in &res.qual {
                assert_ne!(0, node_qual.index)
            }
            filtered.push(res.clone())
        }
    }
    test_results(thr, &filtered)
}

fn test_dkg_nonce_invalid_eviction<S: Scheme>() {
    let n = 7;
    let thr = 4;
    let mut tns = generate_test_nodes::<S>(n);
    let list = nodes_from_test(&tns);
    let conf = Config {
        new_nodes: list,
        threshold: thr,
        ..Default::default()
    };

    fn gen_public<S: Scheme>(thr: u32) -> Vec<KeyPoint<S>> {
        let mut points = Vec::with_capacity(thr as usize);
        for _ in 0..thr {
            points.push(S::sk_to_pk(&S::Scalar::random()))
        }
        points
    }

    fn dm<S: Scheme>(deals: &mut Vec<DealBundle<S>>) {
        deals.index_mut(0).session_id = "Beat It".as_bytes().into();
        assert!(deals[0].dealer_index == 0);
        // Change the public polynomial so it trigggers a response and a justification.
        deals.index_mut(1).public = gen_public::<S>(4);
        assert!(deals[1].dealer_index == 1);
    }

    fn rm(resp: &mut [ResponseBundle]) {
        for bundle in resp.iter_mut() {
            for r in &bundle.responses {
                if bundle.share_index != 0 {
                    assert_ne!(0, r.dealer_index)
                }
            }
            if bundle.share_index == 2 {
                bundle.session_id = "Billie Jean".as_bytes().into()
            }
        }
    }

    let results = run_dkg(&mut tns, conf, Some(dm), Some(rm), None);
    // Nodes [0,1] behaviour is still honest: they are self-evicted (not conributed to results).
    // Node 2 is malicious and need to be removed from results.
    let filtered = results
        .into_iter()
        .filter(|r| r.key.pri_share.index() != 2)
        .collect::<Vec<DkgOutput<S>>>();

    // Final group should be consistent without nodes[0,1,2] materials, they been evicted by final nodes.
    assert!(filtered.len() == 7 - 3);
    test_results(thr, &filtered)
}

fn test_dkg_too_many_complaints<S: Scheme>() {
    let n = 5;
    let thr = 3;
    let mut tns = generate_test_nodes::<S>(n);
    let list = nodes_from_test(&tns);
    let conf = Config {
        new_nodes: list,
        threshold: thr,
        ..Default::default()
    };

    fn dm<S: Scheme>(deals: &mut Vec<DealBundle<S>>) {
        // Make one dealer creating a invalid share for too many participants.
        for i in 0..3 {
            deals[0].deals[i].encrypted_share = "Another one bites the dust".as_bytes().to_vec();
        }
    }
    let results = run_dkg(&mut tns, conf, Some(dm), None, None);
    assert!(results.len() == 4);
    test_results(thr, &results)
}

/// Helper function to run all DKG test cases for given scheme.
fn dkg_cases<S: Scheme>() {
    test_dkg_full_fast::<S>();
    test_dkg_resharing::<S>();
    test_dkg_skip_index::<S>();
    test_dkg_threshold::<S>();
    test_dkg_nonce_invalid_eviction::<S>();
    test_dkg_too_many_complaints::<S>();
    test_self_eviction_dealer::<S>();
    test_self_eviction_share_holder::<S>()
}

#[test]
fn dkg_cases_default() {
    dkg_cases::<DefaultScheme>()
}

#[test]
fn dkg_cases_sigs_on_g1() {
    dkg_cases::<SigsOnG1Scheme>()
}

#[test]
fn dkg_cases_unchained() {
    dkg_cases::<UnchainedScheme>()
}

#[test]
fn dkg_cases_bn254_unchained_on_g1() {
    dkg_cases::<BN254UnchainedOnG1Scheme>()
}
