use libc::execvp;
use linux_perf_data::linux_perf_event_reader::EventRecord;

use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{BufWriter, Read};
use std::os::raw::c_char;
use std::os::unix::prelude::{CommandExt, ExitStatusExt, OsStrExt};
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::perf_event::EventSource;
use super::perf_group::PerfGroup;
use crate::linux_shared::{ConvertRegs, Converter, EventInterpretation};
use crate::server::{start_server_main, ServerProps};

#[cfg(target_arch = "x86_64")]
pub type ConvertRegsNative = crate::linux_shared::ConvertRegsX86_64;

#[cfg(target_arch = "aarch64")]
pub type ConvertRegsNative = crate::linux_shared::ConvertRegsAarch64;

pub fn start_recording(
    output_file: &Path,
    command_name: OsString,
    command_args: &[OsString],
    time_limit: Option<Duration>,
    interval: Duration,
    server_props: Option<ServerProps>,
) -> Result<ExitStatus, ()> {
    let argv: Vec<CString> = std::iter::once(&command_name)
        .chain(command_args.iter())
        .map(|os_str| CString::new(os_str.as_bytes().to_vec()).unwrap())
        .collect();
    let argv: Vec<*const c_char> = argv
        .iter()
        .map(|c_str| c_str.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let (rp, sp) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();

    let pid = match unsafe { nix::unistd::fork() }.expect("Fork failed") {
        nix::unistd::ForkResult::Child => {
            nix::unistd::close(sp).unwrap();
            let mut buf = [0];
            match nix::unistd::read(rp, &mut buf) {
                Ok(0) => std::process::exit(0),
                Ok(_) => {
                    unsafe {
                        let _ = execvp(argv[0], argv.as_ptr());
                    }
                    std::process::exit(-1)
                }
                Err(_) => std::process::exit(1),
            }
        }
        nix::unistd::ForkResult::Parent { child } => {
            nix::unistd::close(rp).unwrap();
            child.as_raw() as u32
        }
    };

    let interval_nanos = if interval.as_nanos() > 0 {
        interval.as_nanos() as u64
    } else {
        1_000_000 // 1 million nano seconds = 1 milli second
    };

    let output_file_copy = output_file.to_owned();
    let command_name_copy = command_name.to_string_lossy().to_string();
    let observer_thread = thread::spawn(move || {
        let perf = init_profiler(interval_nanos, pid);

        // send a byte to the child process
        nix::unistd::write(sp, &[0x42]).expect("Couldn't signal the child process to start");
        nix::unistd::close(sp).unwrap();

        let product = command_name_copy;
        // start profiling pid
        run_profiler(
            perf,
            &output_file_copy,
            &product,
            time_limit,
            interval_nanos,
        );
    });

    // Ignore SIGINT while the subcommand is running. The signal still reaches the process
    // under observation while we continue to record it. (ctrl+c will send the SIGINT signal
    // to all processes in the foreground process group).
    let should_terminate_on_ctrl_c = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    signal_hook::flag::register_conditional_default(
        signal_hook::consts::SIGINT,
        should_terminate_on_ctrl_c.clone(),
    )
    .expect("cannot register signal handler");

    let mut exit_status: i32 = 0;
    let res = unsafe { libc::waitpid(pid as i32, &mut exit_status as *mut libc::c_int, 0) };
    nix::errno::Errno::result(res).expect("couldn't wait for child");
    let exit_status = ExitStatus::from_raw(exit_status);

    // The subprocess is done. From now on, we want to terminate if the user presses Ctrl+C.
    should_terminate_on_ctrl_c.store(true, std::sync::atomic::Ordering::SeqCst);

    observer_thread
        .join()
        .expect("couldn't join observer thread");

    if let Some(server_props) = server_props {
        start_server_main(output_file, server_props);
    }

    Ok(exit_status)
}

fn init_profiler(interval_nanos: u64, pid: u32) -> PerfGroup {
    let frequency = (1_000_000_000 / interval_nanos) as u32;
    let stack_size = 32000;
    let event_source = EventSource::HwCpuCycles;
    let regs_mask = ConvertRegsNative::regs_mask();

    let perf = PerfGroup::open(pid, frequency, stack_size, event_source, regs_mask);

    let mut perf = match perf {
        Ok(perf) => perf,
        Err(error) => {
            eprintln!("Failed to start profiling: {}", error);
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                if let Ok(perf_event_paranoid) =
                    read_string_lossy("/proc/sys/kernel/perf_event_paranoid")
                {
                    if perf_event_paranoid.trim() == "2" {
                        eprintln!();
                        eprintln!("'/proc/sys/kernel/perf_event_paranoid' is set to 2, which is probably why perf_event_open failed.");
                        eprintln!("You can execute the following command and then try again:");
                        eprintln!("    echo '1' | sudo tee /proc/sys/kernel/perf_event_paranoid");
                        eprintln!();
                        eprintln!("This will allow non-root processes to observe perf events.");
                    }
                }
            }

            std::process::exit(1);
        }
    };

    // eprintln!("Enabling perf events...");
    perf.enable();

    perf
}

fn run_profiler(
    mut perf: PerfGroup,
    output_filename: &Path,
    product_name: &str,
    _time_limit: Option<Duration>,
    interval_nanos: u64,
) {
    let cache = framehop::CacheNative::new();

    let first_sample_time = 0;

    let little_endian = cfg!(target_endian = "little");
    let machine_info = uname::uname().ok();
    let interpretation = EventInterpretation {
        main_event_attr_index: 0,
        main_event_name: "cycles".to_string(),
        sampling_is_time_based: Some(interval_nanos),
        have_context_switches: true,
        sched_switch_attr_index: None,
    };

    let mut converter =
        Converter::<framehop::UnwinderNative<Vec<u8>, framehop::MayAllocateDuringUnwind>>::new(
            product_name,
            None,
            HashMap::new(),
            machine_info.as_ref().map(|info| info.release.as_str()),
            first_sample_time,
            little_endian,
            cache,
            None,
            interpretation,
        );

    for event in perf.take_initial_events() {
        match event {
            EventRecord::Comm(e) => {
                converter.handle_thread_name_update(e, Some(0));
            }
            EventRecord::Mmap2(e) => {
                converter.handle_mmap2(e);
            }
            _ => unreachable!(),
        }
    }

    // eprintln!("Running...");

    let mut wait = false;
    let mut pending_lost_events = 0;
    let mut total_lost_events = 0;
    loop {
        if perf.is_empty() {
            break;
        }

        if wait {
            wait = false;
            perf.wait();
        }

        let iter = perf.iter();
        if iter.len() == 0 {
            wait = true;
            continue;
        }

        for event_ref in iter {
            let record = event_ref.get();
            let parsed_record = record.parse().unwrap();
            // debug!("Recording parsed_record: {:#?}", parsed_record);

            match parsed_record {
                EventRecord::Sample(e) => {
                    converter.handle_sample::<ConvertRegsNative>(e);
                    /*
                    } else if interpretation.sched_switch_attr_index == Some(attr_index) {
                        converter.handle_sched_switch::<C>(e);
                    }*/
                }
                EventRecord::Fork(e) => {
                    converter.handle_thread_start(e);
                }
                EventRecord::Comm(e) => {
                    converter.handle_thread_name_update(e, record.timestamp());
                }
                EventRecord::Exit(e) => {
                    converter.handle_thread_end(e);
                }
                EventRecord::Mmap(e) => {
                    converter.handle_mmap(e);
                }
                EventRecord::Mmap2(e) => {
                    converter.handle_mmap2(e);
                }
                EventRecord::ContextSwitch(e) => {
                    let common = match record.common_data() {
                        Ok(common) => common,
                        Err(_) => continue,
                    };
                    converter.handle_context_switch(e, common);
                }
                EventRecord::Lost(event) => {
                    pending_lost_events += event.count;
                    total_lost_events += event.count;
                    continue;
                }
                _ => {}
            }

            if pending_lost_events > 0 {
                eprintln!("Pending lost events: {}", pending_lost_events);
                pending_lost_events = 0;
            }
        }
    }

    if total_lost_events > 0 {
        eprintln!("Lost {} events!", total_lost_events);
    }

    let profile = converter.finish();

    let output_file = File::create(output_filename).unwrap();
    let writer = BufWriter::new(output_file);
    serde_json::to_writer(writer, &profile).expect("Couldn't write JSON");
}

pub fn read_string_lossy<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

pub fn run_helper_process(process_type: &str) {
    match process_type {
        "EXEC" => run_exec_process(),
        _ => panic!("Unexpected helper process type {}", process_type),
    }
}

fn run_exec_process() {
    // We are the exec helper process. Our goal is to exec the target program.
    // We were launched by the root samply process.
    // Now that we exist, the root samply process knows our pid and starts
    // creating the perf event.
    // If the perf event was created successfully, we can start running.
    // Otherwise, we should exit.

    let mut args = std::env::args_os();
    let _self_name = args.next().expect("missing args[0]");
    let command_name = args.next().expect("missing args[1]");
    let command_args = args;

    // We use stdin for communication.
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    // Wait for the root process to tell us to "PROCEED".
    let mut buf = vec![0; b"PROCEED\n".len()];
    match stdin.read_exact(&mut buf) {
        Ok(()) => println!("yo"),
        Err(_) => return,
    };
    match &buf[..] {
        b"PROCEED\n" => {
            let error = Command::new(&command_name).args(command_args).exec();

            // If we get here, the exec failed.
            panic!("launching child unsuccessful: {}", error);
        }
        b"EXIT" => {
            // just return
        }
        _ => panic!("unexpected command {}", String::from_utf8_lossy(&buf)),
    }
}
