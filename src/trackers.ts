/**
 * Built-in tracker and ad-tech domain table. Suffix-matched against
 * hostnames extracted from package sources: `www.google-analytics.com`
 * matches the `google-analytics.com` row, `notgoogle-analytics.com` does
 * not. The list is deliberately small and famous — its job is triage
 * evidence ("this extension phones an analytics network"), not ad
 * blocking; blocklist-scale coverage is a non-goal.
 */

/** What a matched domain is known for. */
export type TrackerCategory = "analytics" | "ads" | "session-replay" | "error-tracking" | "push";

/** domain suffix → category. All lowercase, no leading dot. */
export const TRACKER_DOMAINS: ReadonlyMap<string, TrackerCategory> = new Map<
  string,
  TrackerCategory
>([
  // Analytics & product telemetry
  ["google-analytics.com", "analytics"],
  ["analytics.google.com", "analytics"],
  ["googletagmanager.com", "analytics"],
  ["segment.io", "analytics"],
  ["segment.com", "analytics"],
  ["mixpanel.com", "analytics"],
  ["amplitude.com", "analytics"],
  ["heapanalytics.com", "analytics"],
  ["kissmetrics.io", "analytics"],
  ["matomo.cloud", "analytics"],
  ["statcounter.com", "analytics"],
  ["chartbeat.com", "analytics"],
  ["quantserve.com", "analytics"],
  ["scorecardresearch.com", "analytics"],
  ["mc.yandex.ru", "analytics"],
  ["branch.io", "analytics"],
  ["adjust.com", "analytics"],
  ["appsflyer.com", "analytics"],
  // Session replay (records what the user sees and types)
  ["mouseflow.com", "session-replay"],
  ["hotjar.com", "session-replay"],
  ["fullstory.com", "session-replay"],
  ["clarity.ms", "session-replay"],
  ["logrocket.com", "session-replay"],
  ["inspectlet.com", "session-replay"],
  ["crazyegg.com", "session-replay"],
  ["luckyorange.com", "session-replay"],
  // Advertising networks
  ["doubleclick.net", "ads"],
  ["googlesyndication.com", "ads"],
  ["googleadservices.com", "ads"],
  ["adservice.google.com", "ads"],
  ["connect.facebook.net", "ads"],
  ["adnxs.com", "ads"],
  ["criteo.com", "ads"],
  ["taboola.com", "ads"],
  ["outbrain.com", "ads"],
  ["pubmatic.com", "ads"],
  ["rubiconproject.com", "ads"],
  ["openx.net", "ads"],
  ["moatads.com", "ads"],
  ["amazon-adsystem.com", "ads"],
  // Error tracking (often legitimate, still an exfil channel)
  ["sentry.io", "error-tracking"],
  ["bugsnag.com", "error-tracking"],
  ["nr-data.net", "error-tracking"],
  ["newrelic.com", "error-tracking"],
  ["datadoghq.com", "error-tracking"],
  // Push notification relays
  ["onesignal.com", "push"],
  ["pushwoosh.com", "push"],
]);

/**
 * Match a hostname against the table by registrable-suffix logic:
 * exact match, or ends with "." + domain. Returns the category or null.
 */
export function lookupTracker(host: string): TrackerCategory | null {
  const h = host.toLowerCase();
  for (const [domain, category] of TRACKER_DOMAINS) {
    if (h === domain || h.endsWith(`.${domain}`)) return category;
  }
  return null;
}
