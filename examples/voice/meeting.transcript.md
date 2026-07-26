# Planning sync — orders platform (transcript excerpt)

Format: the ingestion interface is `{turns: [{speaker, at, text}]}`;
markdown here for readability. Any source works — Whisper output, a
platform transcript API, dictation.

---

**[00:03:12] Marta (platform lead):** OK, the orders service. We need
a relational database, production, and it has to live in Warsaw —
legal wants EU residency and we picked europe-central2 last quarter.

**[00:03:40] Tomek (backend):** Postgres, obviously. Sixteen if we
can.

**[00:04:05] Marta:** And absolutely no public exposure. Private
network only — that one's non-negotiable after the audit.

**[00:04:31] Tomek:** Backups... let's say we can lose five minutes,
tops.

**[00:05:02] Marta:** Five minutes RPO, fine. Recovery time — an hour?

**[00:05:19] Tomek:** An hour is fine. Oh — and give it, like, 500
gigs.

**[00:06:44] Marta:** Actually, wait. On the RPO — five minutes is
what the OLD system did. Legal's new retention memo says one minute.
Let's do one minute.

**[00:07:01] Tomek:** One minute it is. PITR then, not snapshots.

**[00:07:15] Marta:** Implementation detail, not our problem here.
One minute of data loss max — that's the requirement.
