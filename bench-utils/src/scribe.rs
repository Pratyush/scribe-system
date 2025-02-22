use std::{
    fs::{File, OpenOptions},
    io::BufReader,
    path::Path,
    time::Instant,
    sync::atomic::AtomicBool,
    thread,
};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use fs_extra::dir::get_size;
use scribe::pc::PCScheme;
use scribe::snark::custom_gate::CustomizedGates;
use scribe::snark::structs::{ProvingKey as _ProvingKey, VerifyingKey as _VerifyingKey};
use scribe::snark::{errors::ScribeErrors, mock::MockCircuit, Scribe};
use scribe::{
    pc::{
        pst13::{srs::SRS, PST13},
        StructuredReferenceString,
    },
    snark::structs::ProvingKeyWithoutCk,
};

type ProvingKey = _ProvingKey<Bls12_381, PST13<Bls12_381>>;
type VerifyingKey = _VerifyingKey<Bls12_381, PST13<Bls12_381>>;

pub fn setup(min_num_vars: usize, max_num_vars: usize, file_dir_path: &Path) {
    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs = timed!(
        "Scribe: Generating SRS",
        PST13::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, max_num_vars).unwrap()
    );

    let srs_path = file_dir_path.join(format!("scribe_srs_{max_num_vars}.params"));
    let srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&srs_path)
        .unwrap();
    let mut srs_file = std::io::BufWriter::new(srs_file);
    timed!(
        "Scribe: Serializing SRS",
        pc_srs.serialize_uncompressed(&mut srs_file).unwrap()
    );
    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    for nv in min_num_vars..=max_num_vars {
        // generate and serialize circuit, pk, vk
        let pk_path = file_dir_path.join(format!("scribe_pk_{nv}.params"));

        let pk_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&pk_path)
            .unwrap();
        let mut pk_file = std::io::BufWriter::new(pk_file);

        let circuit = timed!(
            format!("Scribe: Generating circuit for {nv}"),
            MockCircuit::<Fr>::new(1 << nv, &vanilla_gate)
        );

        let index = circuit.index;

        let (pk, _vk): (ProvingKey, VerifyingKey) = timed!(
            format!("Scribe: Generating pk/vk for {nv}",),
            Scribe::preprocess(&index, &pc_srs).unwrap()
        );

        timed!(
            format!("Scribe: Serializing pk for {nv}"),
            pk.inner.serialize_uncompressed(&mut pk_file).unwrap()
        );
    }
}

pub fn prover(
    min_nv: usize,
    max_nv: usize,
    supported_size: impl Into<Option<usize>>,
    file_dir_path: &Path,
) -> Result<(), ScribeErrors> {
    let supported_size = supported_size.into().unwrap_or(max_nv);
    assert!(max_nv >= min_nv);
    assert!(max_nv <= supported_size);

    let srs: SRS<_> = {
        let srs_path = file_dir_path.join(format!("scribe_srs_{supported_size}.params"));
        let srs_file = open_file(&srs_path);
        let srs_file = std::io::BufReader::new(srs_file);
        let srs = CanonicalDeserialize::deserialize_uncompressed_unchecked(srs_file).unwrap();
        clear_caches();

        srs
    };

    for nv in min_nv..=max_nv {
        // Remove temporary files
        #[cfg(any(target_os = "ios", target_os = "linux"))]
        {
            let tmp_dir = std::env::temp_dir();
            std::fs::read_dir(&tmp_dir).unwrap().for_each(|entry| {
                let entry = entry.unwrap();
                let is_not_ck = !entry.file_name().to_string_lossy().contains("ck_");
                let is_scribe_file = entry.file_name().to_string_lossy().ends_with(".scribe");
                if is_scribe_file && is_not_ck {
                    println!("Removing entry: {}", entry.path().to_string_lossy());
                    std::fs::remove_file(entry.path()).unwrap()
                }
            });
        }

        let pk = {
            let pk_path = file_dir_path.join(format!("scribe_pk_{nv}.params"));
            let pk_file = BufReader::new(open_file(&pk_path));
            let inner = ProvingKeyWithoutCk::deserialize_uncompressed_unchecked(pk_file).unwrap();
            let (pc_ck, _) = srs.trim(nv).unwrap();
            ProvingKey { inner, pc_ck }
        };

        let (public_inputs, witnesses) = timed!(
            format!("Scribe: Generating witness for {nv}"),
            MockCircuit::wire_values_for_index(&pk.index())
        );
        clear_caches();

        let stop_signal = AtomicBool::new(false);

        let proof = thread::scope(|s| {
            let dir_sizes = s.spawn(|| {
                let mut sizes = vec![get_size(file_dir_path).unwrap()];
                while !stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                    let cur_size = get_size(file_dir_path).unwrap();
                    if cur_size != *sizes.last().unwrap() {
                        sizes.push(cur_size);
                    }
                    thread::sleep(std::time::Duration::from_secs(1));
                }
                return sizes;
            });
            let proof = timed!(
                format!("Scribe: Proving for {nv}",),
                Scribe::prove(&pk, &public_inputs, &witnesses).unwrap()
            );
            stop_signal.store(true, std::sync::atomic::Ordering::Relaxed);
            let sizes = dir_sizes.join().unwrap();
            let max_dir_size = sizes.iter().max();
            println!("Sizes.len(): {}", sizes.len());
            println!(
                "Scribe: Directory size for {nv} is: {} bytes",
                max_dir_size.unwrap() - sizes.first().unwrap()
            );
            proof
        });
        

        // Currently verifier doesn't work as we are using fake SRS
        //==========================================================
        // verify a proof
        let result = timed!(
            format!("Scribe: Verifying for {nv}"),
            Scribe::verify(&pk.vk(), &public_inputs, &proof).unwrap()
        );
        if !result {
            eprintln!("Verification failed for {nv}");
        }
    }
    Ok(())
}

fn open_file(file_path: &Path) -> File {
    let file = File::open(file_path).unwrap();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        use libc::{fcntl, F_NOCACHE};
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        let result = unsafe { fcntl(fd, F_NOCACHE, 1) };
        assert_ne!(result, -1);
    }
    file
}

fn clear_caches() {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sync")
            .status()
            .expect("failed to sync file");

        std::process::Command::new("sudo")
            .arg("purge")
            .status()
            .expect("failed to purge fs cache");
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::{Command, Stdio};
        let echo = Command::new("echo")
            .arg("3")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start echo");

        let mut tee = Command::new("sudo")
            .arg("tee")
            .arg("/proc/sys/vm/drop_caches")
            .stdin(Stdio::piped())
            .stdout(Stdio::null()) // To suppress tee's stdout
            .spawn()
            .expect("Failed to start tee");

        if let Some(mut echo_stdout) = echo.stdout {
            if let Some(mut tee_stdin) = tee.stdin.take() {
                std::io::copy(&mut echo_stdout, &mut tee_stdin).expect("Failed to write to tee");
            }
        }

        tee.wait().expect("Failed to wait for tee");
    }
}
