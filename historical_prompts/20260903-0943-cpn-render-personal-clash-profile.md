# 20260903-0943-cpn — render a personal Clash profile

The user asked to move personal-node Clash ownership out of `~/.claude-sync` and into the
Czyhandsome/trojan project. The agreed result is a small CLI plus README guidance that renders one
manually selectable Profile containing Aiyun1, Aiyun2, Solo-green and DIRECT, with Aiyun1 as the
default. Passwords remain in the personal Keychain profile, while a tracked YAML template owns the
current lightweight rules and can be edited before later rerenders. The current Mac should import
and validate the generated Profile, then remove only the three superseded local profiles while
leaving the two paid remote subscriptions unchanged.
