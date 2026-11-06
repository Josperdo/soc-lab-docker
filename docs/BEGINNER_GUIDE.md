# Beginner Guide: Your First Detection Query

This guide walks you through the complete detection engineering workflow end-to-end — from spinning up the lab, to simulating an attack, to writing a query that catches it. No prior SIEM experience required.

By the end, you will have:
- Generated real attack events in the lab
- Located those events in Kibana
- Run a detection query against them
- Understood why the query works and how to tune it

---

## What We're Detecting

**Brute force authentication** — an attacker repeatedly guessing passwords against a login service (SSH in this case) until they find a valid credential.

It's a good first detection because:
- The attack pattern is simple and intuitive
- The signal-to-noise ratio is high (many failures from one IP in a short window)
- It maps directly to a real-world threat: **MITRE ATT&CK T1110.001**

---

## Step 1: Start the Lab

```bash
docker-compose up -d
```

Wait about 60 seconds for all services to initialize, then verify:

```bash
docker-compose ps
```

All services should show `Up`. Open Kibana at `http://localhost:5601`.

---

## Step 2: Simulate the Attack

The lab includes a brute force simulation script that generates realistic failed authentication events:

```bash
./scripts/brute_force_simulation.sh \
  --target-user admin \
  --attempt-count 50 \
  --delay-ms 100
```

This generates 50 failed SSH authentication events from a simulated attacker IP, followed by a successful login — the pattern an attacker produces after finding a valid credential.

---

## Step 3: Find the Events in Kibana

Before writing a detection, explore the raw data to understand what you're working with.

1. Open Kibana → **Discover**
2. Select the `soc-lab*` index pattern
3. Set the time range to **Last 15 minutes**
4. In the search bar, enter:

   ```
   event.category: "authentication" AND event.outcome: "failure"
   ```

5. Press Enter

You should see 50 events from the simulation. Click one to expand it and examine the fields:

| Field | What it tells you |
|---|---|
| `source.ip` | Where the authentication attempt came from |
| `user.name` | Which account was targeted |
| `host.name` | Which system was targeted |
| `authentication.service` | Which service (sshd, rdp, etc.) |
| `event.outcome` | `failure` or `success` |
| `@timestamp` | When it happened |

This is your raw material. A detection query is just a structured way of asking: "show me events that match a suspicious pattern."

---

## Step 4: Understand the Detection Logic

A single failed login is noise — everyone mistype passwords. The signal is **many failures from the same source in a short time window**.

The detection logic in plain English:
1. Find all authentication failure events
2. Group them by source IP and 5-minute time bucket
3. Count the failures per group
4. Alert when the count exceeds a threshold (10 in this case)

---

## Step 5: Run the Detection Query

### Kibana ES|QL (recommended for this lab)

Open Kibana → **Discover** → toggle to **ES|QL** mode (top-left dropdown).

Run this query:

```esql
FROM soc-lab*
| WHERE event.category == "authentication"
  AND event.outcome == "failure"
| EVAL time_bucket = DATE_TRUNC(5 minutes, @timestamp)
| STATS
    failure_count = COUNT(*),
    unique_users  = COUNT_DISTINCT(user.name),
    unique_hosts  = COUNT_DISTINCT(host.name)
  BY source.ip, time_bucket
| WHERE failure_count > 10
| SORT failure_count DESC
| LIMIT 100
```

You should see one row: the simulated attacker IP with 50 failures.

### Breaking it down line by line

```esql
FROM soc-lab*
```
Query all SOC lab indices.

```esql
| WHERE event.category == "authentication"
  AND event.outcome == "failure"
```
Filter to only authentication failure events. This is the base filter — everything else builds on it.

```esql
| EVAL time_bucket = DATE_TRUNC(5 minutes, @timestamp)
```
Group timestamps into 5-minute buckets. This is how we detect bursts — failures spread over hours look different from failures crammed into 5 minutes.

```esql
| STATS failure_count = COUNT(*), ...
  BY source.ip, time_bucket
```
Count failures per source IP per 5-minute window. This is the aggregation that turns individual events into a meaningful signal.

```esql
| WHERE failure_count > 10
```
Apply the threshold. Below 10, it could be a user who forgot their password. Above 10, it's almost certainly automated.

---

## Step 6: Verify the Full Picture

Now check whether the attacker succeeded. Run this query to find authentications where failures were followed by a success from the same IP:

```esql
FROM soc-lab*
| WHERE event.category == "authentication"
  AND source.ip == "REPLACE_WITH_ATTACKER_IP"
| STATS
    failures = COUNT(CASE WHEN event.outcome == "failure" THEN 1 END),
    successes = COUNT(CASE WHEN event.outcome == "success" THEN 1 END)
  BY source.ip
| LIMIT 100
```

Replace `REPLACE_WITH_ATTACKER_IP` with the IP from the previous result. A non-zero `successes` value means the attacker found a valid credential — this is a higher-severity finding.

---

## Step 7: Tune the Threshold

The threshold (`failure_count > 10`) is a starting point, not a law. Tuning it requires knowing your environment:

**Too low (e.g., > 3):** You get alerts for users who mistype their password twice. High false-positive rate. Analysts stop trusting the alert.

**Too high (e.g., > 100):** A slow brute force (one attempt per minute) will never trigger. Attackers deliberately slow down to avoid thresholds.

**How to find the right number:**
1. Run the query over a week of normal data with `failure_count > 1`
2. Look at the distribution — what's the 95th percentile failure count per IP per 5 minutes during normal operations?
3. Set your threshold just above that

This is **baseline methodology** — the most important skill in detection engineering. The query is just the mechanism; understanding normal behavior is the craft.

---

## What You Just Did

- Generated a realistic attack event chain
- Explored raw events to understand the data model
- Wrote an aggregation query that converts noisy events into a meaningful signal
- Applied a threshold based on the attack pattern
- Verified attacker success as a secondary enrichment step
- Understood the trade-off between false positives and false negatives

This is the full detection engineering loop. Every detection in this lab — and in production SIEMs — follows the same pattern.

---

## Next Steps

- **Explore the other detection queries** in `detections/` — each one is annotated with the same methodology
- **Run the other attack simulations** in `scripts/` and try to detect them using the pattern you just learned
- **Build your own detection** — the [Intermediate Guide](INTERMEDIATE_GUIDE.md) walks through creating a new detection from scratch
