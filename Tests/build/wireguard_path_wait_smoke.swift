import Foundation

@main
struct WireGuardPathWaitSmoke {
    static func main() {
        var episode = WireGuardPathWaitGeneration()
        precondition(!episode.waiting && !episode.accepts(0))
        let first = episode.beginWait()!
        precondition(episode.waiting && episode.accepts(first))
        precondition(episode.beginWait() == nil, "Duplicate waiting created a second timer")
        episode.invalidate() // ready/cancel
        precondition(!episode.waiting && !episode.accepts(first))
        let second = episode.beginWait()!
        precondition(second != first && episode.accepts(second))
        precondition(!episode.accepts(first))
        episode.invalidate() // transport teardown
        precondition(!episode.accepts(second))
        for _ in 0..<4096 {
            let pending = episode.beginWait()!
            precondition(episode.accepts(pending))
            episode.invalidate() // recovered or stopped
            precondition(!episode.accepts(pending))
        }
        print("BoringTun UDP wait watchdog: duplicate, recovered, stale and restart episodes passed")
    }
}
