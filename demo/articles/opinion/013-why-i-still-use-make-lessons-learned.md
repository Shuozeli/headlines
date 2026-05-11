---
title: "Why I Still Use Make: Lessons Learned"
author_name: "Jamie Quill"
author_url: "https://example.com"
created_at: "2026-04-20T23:56:00Z"
state: "live"
---

**Followup:** since publishing the original I've learned a few more things worth recording.


There's no language a programmer invents in a weekend that can't be
made worse than `make`. And yet `make` keeps winning, because it
actually does the thing you want.

Boring infrastructure wins. Make is boring. I will go on using it.


Yes, `make` has its quirks. Tabs versus spaces. The macro language
that's not really a language. The whitespace handling that makes
your eyes water. None of that matters as much as: you can `cat
Makefile` and read it.

What `make` does is: declare a graph of files and dependencies, run
only the parts that are stale, and hand you a uniform interface
(`make <target>`) for everything. Every modern build tool either
reinvents this or fights it. The reinventors usually do worse.
