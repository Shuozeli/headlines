---
title: "Self-Hosting a Postgres Instance with WAL Archiving: Part 2"
author_name: "Priya Shah"
author_url: "https://example.com"
created_at: "2026-04-28T06:25:00Z"
state: "live"
---

**Followup:** since publishing the original I've learned a few more things worth recording.


Self-hosting Postgres for a personal project or small-team service is a
fine choice. The operational discipline you'd apply to a production
deployment is overkill, but the basic safety net — point-in-time
recovery via WAL archiving — is well worth setting up.

The setup we're building:

## Architecture

This tutorial walks through configuring a single-node Postgres 16
instance with continuous WAL archiving to local disk, plus the recovery
procedure.

- A Postgres data directory on `/var/lib/postgresql/16/main`.
- A WAL archive directory on a *separate* mount, e.g.
  `/srv/wal-archive`.
- A periodic `pg_basebackup` to a third location for full snapshots.
- A simple recovery procedure documented in `RUNBOOK.md`.

Why a separate mount? Because the failure mode you're protecting
against is "data directory disk dies." If your archive lives on the
same disk, you've protected against nothing.

## Step 1: postgresql.conf

```ini
wal_level = replica
archive_mode = on
archive_command = 'cp %p /srv/wal-archive/%f'
archive_timeout = 300  # force a segment switch every 5 minutes
```

The `archive_timeout` matters when traffic is light. Without it, a
quiet Postgres instance might not switch WAL segments for hours, and
all the writes between switches are at risk.

## Step 2: Provision the archive mount

```bash
mkfs.ext4 /dev/sdb1
mkdir /srv/wal-archive
mount /dev/sdb1 /srv/wal-archive
chown postgres:postgres /srv/wal-archive
```

Add the mount to `/etc/fstab` so it survives reboots.

## Step 3: Restart Postgres

```bash
systemctl restart postgresql@16-main
```

Watch the logs. You should see lines confirming `archive_mode = on`.

## Step 4: Verify archiving

Force a segment switch and check the archive:

```sql
SELECT pg_switch_wal();
```

```bash
ls /srv/wal-archive
```

You should see at least one new file with a 24-character hex name.

## Step 5: Take a base backup

```bash
sudo -u postgres pg_basebackup -D /srv/basebackups/$(date +%F) -X stream -P
```

Run this nightly via cron. Keep two weeks' worth.

## Step 6: Recovery procedure

To recover to a specific point in time:

```bash
systemctl stop postgresql@16-main
rm -rf /var/lib/postgresql/16/main/*
cp -a /srv/basebackups/<recent>/* /var/lib/postgresql/16/main/
echo "restore_command = 'cp /srv/wal-archive/%f %p'" >> /var/lib/postgresql/16/main/postgresql.auto.conf
echo "recovery_target_time = 'YYYY-MM-DD HH:MM:SS+00'" >> /var/lib/postgresql/16/main/postgresql.auto.conf
touch /var/lib/postgresql/16/main/recovery.signal
systemctl start postgresql@16-main
```

Postgres will replay WAL up to the target time and then enter normal
operation.

## Caveats

Local-disk archives don't protect against datacenter loss. For anything
remotely production-shaped, ship the archives to object storage with
something like `pgbackrest` or `wal-g`. Both wrap this entire workflow
into one tool, which is what you actually want at scale.

But for a personal Postgres? Local disk on a separate mount is
genuinely fine, and the recovery procedure above has worked the half
dozen times I've needed it.
