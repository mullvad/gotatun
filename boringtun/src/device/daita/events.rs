use super::types::{self, MachineTimer, MachineTimers};
use futures::FutureExt;
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::RngCore;
use tokio::{sync::mpsc, time::Instant};

pub(super) async fn handle_events<M, R>(
    mut maybenot: Framework<M, R>,
    mut event_rx: mpsc::UnboundedReceiver<TriggerEvent>,
    event_tx: mpsc::WeakUnboundedSender<TriggerEvent>,
    action_tx: mpsc::UnboundedSender<(types::Action, MachineId)>,
) -> Option<()>
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
{
    let mut machine_timers = MachineTimers::new(maybenot.num_machines() * 2);
    let mut event_buf = Vec::new();

    loop {
        futures::select! {
            _ = event_rx.recv_many(&mut event_buf, usize::MAX).fuse() => {
                if event_buf.is_empty() {
                    log::debug!("DAITA: event_rx channel closed, exiting handle_events");
                    return None; // channel closed
                }
            },
            (machine, timer) = machine_timers.wait_next_timer().fuse() => {
                match timer {
                    MachineTimer::Action(action_type) => action_tx
                        .send((action_type, machine))
                        .ok(),
                    MachineTimer::Internal => event_tx
                        .upgrade()?
                        .send(TriggerEvent::TimerEnd { machine })
                        .ok(),
                }?;
                continue;
            }
        }
        let actions = maybenot.trigger_events(event_buf.as_slice(), Instant::now().into()); // TODO: support mocked time?
        event_buf.clear();
        for action in actions {
            match action {
                TriggerAction::Cancel { machine, timer } => match timer {
                    maybenot::Timer::Action => machine_timers.remove_action(machine),
                    maybenot::Timer::Internal => machine_timers.remove_internal(machine),
                    maybenot::Timer::All => machine_timers.remove_all(machine),
                },
                TriggerAction::SendPadding {
                    timeout,
                    bypass,
                    replace,
                    machine,
                } => {
                    machine_timers.schedule_padding(*machine, *timeout, *replace, *bypass);
                }
                TriggerAction::BlockOutgoing {
                    timeout,
                    duration,
                    bypass,
                    replace,
                    machine,
                } => {
                    machine_timers.schedule_block(*machine, *timeout, *duration, *replace, *bypass);
                }
                TriggerAction::UpdateTimer {
                    duration,
                    replace,
                    machine,
                } => {
                    if machine_timers.schedule_internal_timer(*machine, *duration, *replace) {
                        event_tx
                            .upgrade()?
                            .send(TriggerEvent::TimerBegin { machine: *machine })
                            .ok()?;
                    }
                }
            }
        }
    }
}
