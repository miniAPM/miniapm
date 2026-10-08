use state_machines::state_machine;

#[cfg(test)]
mod tests;

state_machine! {
    name: ErrorStatus,
    dynamic: true,
    initial: Open,
    states: [Open, Resolved, Ignored],
    events {
        resolve { transition: { from: [Open, Ignored], to: Resolved } }
        ignore { transition: { from: [Open, Resolved], to: Ignored } }
        reopen { transition: { from: [Resolved, Ignored], to: Open } }
        recur { transition: { from: Resolved, to: Open } }
    }
}

const STATES: [&str; 3] = ["open", "resolved", "ignored"];

/// Every `(from, to)` status pair a recurring error moves between
pub fn recur_transitions() -> impl Iterator<Item = (&'static str, &'static str)> {
    STATES
        .into_iter()
        .filter_map(|from| Some((from, transition(from, ErrorStatusEvent::Recur)?)))
}

/// The status after `event`, or `None` when `status` is unknown or does not
/// allow `event`
pub fn transition(status: &str, event: ErrorStatusEvent) -> Option<&'static str> {
    let state = match status {
        "open" => ErrorStatusState::Open,
        "resolved" => ErrorStatusState::Resolved,
        "ignored" => ErrorStatusState::Ignored,
        _ => return None,
    };
    let mut machine = DynamicErrorStatus::new_init_state((), state);
    machine.handle(event).ok()?;
    Some(match machine.current_state() {
        ErrorStatusState::Open => "open",
        ErrorStatusState::Resolved => "resolved",
        ErrorStatusState::Ignored => "ignored",
    })
}
