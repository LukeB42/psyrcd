# mud.py — +mud channel mode plugin for psyrcd.
# Luke Brooks, 2026. MIT License.
MUD_DB = 'mud.db'
MUD_MODEL= 'ministral-3:3b'
"""
+mud Channel Mode — Design Reference
======================================

Overview
--------
mud.py implements a +mud channel mode for psyrcd. Setting +mud on a channel
transforms it into a persistent, multi-user dungeon hosted entirely within the
IRC channel. All game I/O is delivered as PRIVMSG lines to the channel from a
pseudo-identity derived from the channel name. No NOTICE, no CTCP, no direct
PRIVMSG to client nicks — everything is contained in the channel.

Activation
----------
    /mode #foo +mud             — defaults to base game Default; world: default_foo
    /mode #foo +mud:cyberpunk   — base game Cyberpunk;           world: cyberpunk_foo
    /mode #foo +mud:void        — base game Void;                world: void_foo

The argument to +mud is a base game name (default, cyberpunk, void). The
actual world name is always derived automatically as {base}_{channel}, where
channel is the channel name without the leading #. This means:

  - Every channel gets its own independent world. Two channels running
    +mud:default are running default_foo and default_bar — entirely separate.
  - If a world named {base}_{channel} already exists in sqlite (from a previous
    +mud activation on this channel), it is resumed exactly as left.
  - If no such world exists, it is freshly seeded from the base game template.
  - The base game templates are seed definitions in the plugin, not live sqlite
    worlds. They are never directly modified by player or admin activity.

Omitting the argument is equivalent to +mud:default.

Multiple channels may each run different base games simultaneously, each with
their own independently evolving world.

Message Delivery
----------------
All MUD output uses a single mechanism:

    :adventure!adventure@irc.theserverweareon.tld PRIVMSG #adventure :text

The pseudo-identity is derived at runtime: strip the # from the channel name,
use SRV_DOMAIN for the host. No fake IRCClient is registered. Messages are
written directly to client.request.send() for each intended recipient.

Three delivery scopes:
  - Room-scoped:     sent to every channel member currently in the same room
                     (combat, NPC actions, arrivals, departures).
  - Personal:        sent only to the requesting client (look, inventory,
                     stats, damage taken, your own actions).
  - Admin broadcast: sent to all channel members via explicit admin command.
                     A boss spawning does NOT alert all players — it is only
                     known to players in the same room.

Normal channel PRIVMSG is intercepted and suppressed entirely. Players' typed
commands are never echoed to other clients. Only MUD-crafted response lines
flow out.

msg() Helper
------------
    msg(client, channel, text, color=None)

Constructs and sends a PRIVMSG from the channel pseudo-identity to the given
client. If color is specified, prepends the IRC color code and appends \x0f
reset. Performs a post-processing pass: any \x0f inside the text is replaced
with \x0f\x03{base_color} so inline-colored words return to the message base
color rather than the terminal default.

If the player's 'colors' flag in sqlite is False, all IRC formatting codes
(\x03 color, \x02 bold, \x1d italic, \x1f underline, \x0f reset) are stripped
before delivery. Toggled in-game with: colors on / colors off

paint(text, color) wraps a substring in IRC color codes for inline use.

Color constants live in a small C namespace (C.DAMAGE, C.HEAL, C.LOOT, etc.)
mapping to IRC color integers so call sites express intent rather than magic
numbers.

Semantic Color Palette
----------------------
  General narration / room descriptions  — no base color (terminal default)
  Damage taken                           — Red (4)
  Damage dealt                           — Brown/Dark Red (5)
  Death messages                         — bold Dark Red (5)
  Healing / regen tick                   — Light Green (9)
  XP gain                                — Yellow (8)
  Level-up line                          — bold Yellow (8)
  Item names (inline)                    — Yellow (8)
  Spell / hack names (inline)            — Light Cyan (11)
  NPC names (inline, by danger tier)     — Gray (14) trivial, White (0) normal,
                                           Yellow (8) notable, Red (4) dangerous,
                                           bold Red (4) boss-tier
  Exit directions (inline)               — underlined
  Player names (inline)                  — bold, no color change
  Admin broadcast                        — bold Magenta (6)
  Safe room arrival                      — Light Gray (15)
  Currency amounts (inline)              — Yellow (8)
  Critical hit                           — bold Red (4)
  System / error messages                — Dark Gray (14)
  Death observer state messages          — italic Dark Gray (14)

handle_join Intercept
---------------------
When a client joins a +mud channel, handle_join is intercepted to check for an
existing player record in sqlite:

  Returning player — restore last safe room, calculate offline passive regen
                     (capped at 30 minutes), send room description as first
                     message: "You wake up in the inn. Your wounds have healed
                     slightly."

  New player       — character creation wizard starts immediately. Commands
                     route to the creation flow rather than the game dispatcher
                     until a guild is chosen and the character is placed in the
                     world's start room. Until then the player is guildless with
                     only 'attack' and 'flee' available.

Death and Respawning
--------------------
On death the player enters a read-only observer state. All room events continue
to arrive normally. Any command issued while dead returns:

    "You hover over your body and look on in horror."

No commands take effect. The player's inventory remains on their corpse in the
room and can be looted by other players or NPCs. On respawn the player is
placed at their last safe room carrying whatever inventory remains on the
corpse; the corpse object is removed.

Respawn delay scales with level:
    delay = 10 / level   (seconds)
    Level 1 → 10s, Level 5 → 2s, Level 10 → 1s, Level 100 → 0.1s

The countdown is managed by the AI director.

Stats: Blood and Stamina
------------------------
Blood — hit points. Losing all blood kills the player.
Stamina — action resource. Required for spells, special attacks, costly actions.

Both maximum values scale with level.

Passive regen (handled exclusively by the AI director):
  Blood:   1 point per 120 seconds (very slow, always active).
  Stamina: 1 point per max(2, 30 - level // 5) seconds (scales with level).

Offline catch-up regen is calculated from player.last_seen on rejoin, capped
at 30 minutes worth of ticks. This prevents logging off as a healing strategy
while still rewarding reasonable rest periods.

Active recovery via items and spells is substantially faster than passive regen.

Leveling
--------
XP required to advance from level N to N+1:
    needed = current_total_xp * factor

where factor is a tunable constant (suggested range 1.3–2.0). This is
exponential and self-calibrating: the target always scales with everything the
player has already earned.

Players level up quickly at first and increasingly slowly thereafter, satisfying
the design goal: "level up almost immediately, then harder and harder."

Stat Growth on Level Up
-----------------------
On levelling from L to L+1, max_blood and max_stamina increase by:
    blood_gain   = floor(5 * (L+1) * guild_blood_factor)
    stamina_gain = floor(3 * (L+1) * guild_stamina_factor)

Guild factors:
              blood_factor   stamina_factor
  Warrior:       1.5            0.8
  Mage:          0.8            1.5
  Rogue:         1.0            1.2
  Cleric:        1.1            1.1
  (Cyberpunk guilds use the exact same factors as their Default equivalents.)

The new level is factored in directly so gains accelerate — a Warrior going
from level 9→10 gains floor(5*10*1.5)=75 blood; from 49→50 gains 375 blood.
High-level characters are substantially tankier than low-level ones, which
matches the exponential XP curve.

Guild Abilities and Switching
------------------------------
Joining a guild requires finding and talking to that guild's master NPC in the
world (Guild Master in the default world; Talent Agent in the cyberpunk world).
Until then the player is guildless with only 'attack' and 'flee'.

Guild changes are free and permanent. All previously earned skills are retained.
Players can change guild at any time by finding the Guild Master (default) or
Talent Agent (cyberpunk) and typing: guild <name>

The 'guild' command also works standalone: 'guild' lists available guilds;
'guild <name>' switches to the named guild.

Guild NPC location (default): Town Square → west → Market Street → west
→ Guild Quarter → west → Guild Hall (Guild Master)

Guild NPC location (cyberpunk): Corporate Plaza → west → Transit Hub → west
→ Talent Bureau → west → Talent Agency (Talent Agent)

Each guild tracks its own guild_level independently. Switching guilds does not
erase prior guild levels or abilities — a player who was a level 12 Warrior
before switching to Mage keeps Whirlwind and can still use it, while beginning
to accumulate Mage guild levels and unlocking spells. Abilities are additive
across a player's history.

Guild level is tracked per guild in the guild_levels table. A player's current
active guild is stored in players.guild.

First skills are earned at guild level 2 (not 1). New players spend at least
one guild level before unlocking any ability, encouraging learning through
basic combat first.

Default World Guilds
--------------------
Warriors receive an additive melee bonus:
    warrior_bonus = floor(warrior_guild_level * 0.5)
applied as: damage = max(0, attack + weapon.damage + roll(1,6)
                             + warrior_bonus - defender.defense)

  Warrior
    shield bash        (guild level  2)
    berserk            (guild level  4)
    whirlwind          (guild level  6)
    taunt              (guild level  8)
    leech              (guild level 10)
    blind              (guild level 12)
    bind               (guild level 14)
    shatter            (guild level 16)
    blood pact         (guild level 18)
    ward               (guild level 20)
    time stop          (guild level 22)
    shockwave          (guild level 24)
    maelstrom          (guild level 26)
    void walk          (guild level 28)
    apotheosis         (guild level 30)
    apocalypse         (guild level 32)

  Rogue
    stealth            (guild level  2)
    backstab           (guild level  4)
    pickpocket         (guild level  6)
    poison blade       (guild level  8)
    leech              (guild level 10)
    evasion            (guild level 12)
    shatter            (guild level 14)
    absorb             (guild level 16)
    bind               (guild level 18)
    blood pact         (guild level 20)
    ward               (guild level 22)
    shockwave          (guild level 24)
    void walk          (guild level 26)
    mind control       (guild level 28)
    maelstrom          (guild level 30)
    apotheosis         (guild level 32)

  Mage
    magic missile      (guild level  2)
    fireball           (guild level  4)
    chain lightning    (guild level  6)
    ice storm          (guild level  8)
    drain              (guild level 10)
    detect             (guild level 12)
    meteor             (guild level 14)
    time stop          (guild level 16)
    absorb             (guild level 18)
    consecrate         (guild level 20)
    bind               (guild level 22)
    apocalypse         (guild level 24)
    singularity        (guild level 26)
    void walk          (guild level 28)
    apotheosis         (guild level 30)
    time warp          (guild level 32)

  Cleric
    heal               (guild level  2)
    bless              (guild level  4)
    mend               (guild level  6)
    smite              (guild level  8)
    resurrect          (guild level 10)
    rally              (guild level 12)
    ward               (guild level 14)
    consecrate         (guild level 16)
    spirit link        (guild level 18)
    bind               (guild level 20)
    time stop          (guild level 22)
    divine intervention(guild level 24)
    necromancy         (guild level 26)
    soul steal         (guild level 28)
    apotheosis         (guild level 30)
    void walk          (guild level 32)

Cyberpunk World Guilds (exact mappings)
----------------------------------------
  Mercenary (≡ Warrior) — same melee bonus formula, same guild level thresholds
    flash bang         (guild level  2)
    combat stims       (guild level  4)
    suppressive fire   (guild level  6)
    provoke            (guild level  8)
    power drain        (guild level 10)
    sensor jam         (guild level 12)
    root access        (guild level 14)
    deconstruct        (guild level 16)
    risk protocol      (guild level 18)
    firewall           (guild level 20)
    system freeze      (guild level 22)
    emp burst          (guild level 24)
    feedback loop      (guild level 26)
    dark net           (guild level 28)
    godmode            (guild level 30)
    zero day           (guild level 32)

  Ghost (≡ Rogue) — specialises in ranged weapons, stealth, and covert ops
    ghost protocol     (guild level  2)
    execution          (guild level  4)
    pickpocket         (guild level  6)
    nano-toxin         (guild level  8)
    power drain        (guild level 10)
    evasion            (guild level 12)
    deconstruct        (guild level 14)
    data harvest       (guild level 16)
    root access        (guild level 18)
    risk protocol      (guild level 20)
    firewall           (guild level 22)
    emp burst          (guild level 24)
    dark net           (guild level 26)
    puppet master      (guild level 28)
    feedback loop      (guild level 30)
    godmode            (guild level 32)

  Netrunner (≡ Mage) — hacks replace spells, bypass physical defense
    hack               (guild level  2)
    system crash       (guild level  4)
    arc discharge      (guild level  6)
    ice breaker        (guild level  8)
    data siphon        (guild level 10)
    analyze            (guild level 12)
    data nuke          (guild level 14)
    system freeze      (guild level 16)
    data harvest       (guild level 18)
    overwrite          (guild level 20)
    root access        (guild level 22)
    zero day           (guild level 24)
    kernel panic       (guild level 26)
    dark net           (guild level 28)
    godmode            (guild level 30)
    clock spike        (guild level 32)

  Ripperdoc (≡ Cleric)
    patch up           (guild level  2)
    overclock          (guild level  4)
    nano-heal          (guild level  6)
    shock              (guild level  8)
    resurrect          (guild level 10)
    broadcast boost    (guild level 12)
    firewall           (guild level 14)
    overwrite          (guild level 16)
    sync link          (guild level 18)
    root access        (guild level 20)
    system freeze      (guild level 22)
    emergency override (guild level 24)
    reboot             (guild level 26)
    clock spike        (guild level 28)
    godmode            (guild level 30)
    dark net           (guild level 32)

Void world guilds, ability names, and acquisition methods are fully
admin-defined via @world commands.

Channel Operators as Admins
----------------------------
Channel op tiers map directly to MUD admin privilege tiers:
  ~  (owner/q)  — full control including destructive operations
  &  (admin/a)  — edit world, NPCs, rooms, players; cannot wipe/reset
  @  (op/o)     — standard admin: teleport, broadcast, edit descriptions
  %  (halfop/h) — limited: view admin info (@who, @rooms, @spawn list)
  (no status)   — regular player

Admin commands are prefixed with @:

  Listing (halfop % and above):
  @list rooms                    list all rooms (id, name, safe status)
  @list npcs [query]             list NPC templates (partial name search)
  @list items [query]            list item templates
  @list bans                     list world bans
  @list players [all]            list online players (all = ever created)
  @list themes                   list generation themes
  @list quests                   list quest definitions
  @generate preview <theme> <size> <difficulty>  preview without committing

  Building (op @ and above):
  @create room <dir> [name]      create a room attached to current in direction
  @attach <room_id> <dir>        wire bidirectional exit current ↔ room_id
  @attach <room_id> <dir> --oneway  one-directional only
  @modify room <desc|name|exit|safe> [...]  edit current room (same as @room)
  @announce <text>               broadcast to all channel members
  @goto <room_name|nick>         teleport to a room name or player nick
  @kick <nick> [reason]          eject player from the world (stays in channel)
  @freeze <nick>                 immobilise a player (cannot move or act)
  @unfreeze <nick>               release a frozen player
  @spawn npc <name|id>           spawn an NPC instance into the current room
  @spawn prop <name|id>          spawn a prop/item into the current room
  @generate area <theme> <size> <difficulty>   generate and attach a new area
  @generate room <type> <theme>  generate and attach a single room

  Admin (& and above):
  @create npc <name>             create an NPC template in the current room
  @create theme <name>           create a new empty generation theme
  @modify npc <...>              edit NPC template (same as @npc)
  @modify player <nick> <field> <value>  edit a player's record
  @modify world <field> <value>  edit world metadata
  @ban <nick> [reason]           ban player from participating in this world
  @unban <nick>                  remove a world ban
  @spawn copy npc <world:id|n>   copy NPC template from another world
  @spawn copy prop <world:id|n>  copy prop template from another world
  @spawn list npcs [query] [--all]    substring search NPC templates (all worlds)
  @spawn list props [query] [--all]   substring search item templates (all worlds)
  @theme create <name>           create a new empty theme
  @theme fragments/fragment/words/word/npc/loot/ambient ...  (see help @theme)

  Owner (~ only):
  @reset world                   wipe and reinitialise the world

  Legacy aliases (still work, but @create/@modify/@list preferred):
  @rooms     — same as @list rooms
  @room      — same as @modify room
  @npc       — same as @create npc / @modify npc
  @player    — same as @modify player
  @world     — same as @modify world
  @ban list  — same as @list bans
  @who       — same as @list players
  @who all   — same as @list players all

NAMES compatibility: players are real IRC clients in the channel. NAMES works
without modification. NPCs have no IRC presence; their actions and speech are
emitted as narration lines from the channel pseudo-identity.

The AI Director
---------------
One asyncio task per world, running on a 1-second base interval.

Each NPC instance carries a next_action_at Unix timestamp. The director only
processes an NPC when time.time() >= next_action_at, giving each NPC its own
effective tick rate without multiple loops:
  Idle / sleeping NPC:      next_action_at = now + 30
  Patrolling NPC:           next_action_at = now + 8
  Combat-engaged NPC:       next_action_at = now + 2
  Stunned NPC:              next_action_at = now + stun_duration

NPC state machine:
  idle → patrol → aggressive ──(MarkovNet brain)──→ fleeing → dead → respawning
                ↳ aggressive_talker (talks on detect, attacks if provoked)

The director also handles:
  - Passive blood/stamina regen for all online players
  - Respawn countdowns for dead players
  - Corpse expiry (configurable per world, default 5 minutes)
  - Periodic sqlite flushes of dirty player/NPC state
  - Per-room tension tracking and dynamic difficulty scaling (see below)
  - Status effect tick-down and expiry for players and NPCs

NPC brains, state, and respawn timers persist in sqlite so they survive
server restarts.

NPC Patrol Paths
----------------
Patrolling NPCs use a random walk weighted by room adjacency. On each patrol
tick the NPC selects the next room from a ProbDist over its current room's
exits, with weights adjusted by the NPC's danger tier vs the room's level
bracket — an NPC will not cross into a room whose level bracket is more than
one tier above its own danger_tier. This keeps low-tier NPCs from wandering
into endgame areas and high-tier NPCs from flooding starter rooms.

NPC Target Selection
---------------------
In combat, an NPC always targets the player who most recently hit it. If that
player leaves the room or dies, the NPC retargets the next player in the room
who has dealt it damage (tracked by instance-level hit_log in memory), falling
back to a random player in the room, then returning to patrol if the room is
empty of valid targets.

NPC Respawn Location
---------------------
Each npc_instance stores spawn_room_id at creation time. On respawn the AI
director moves the instance back to spawn_room_id, resets blood to template
max, and sets state to idle. The director owns this entirely — no player or
admin input is needed. Instances created via @spawn use the room they were
spawned in as spawn_room_id.

AI Director Task Registry
--------------------------
One asyncio task per active world. Tasks are stored in a module-level dict:
    _directors: dict[world_name, asyncio.Task]
and also referenced on ctx.client.server (the IRCServer instance) as:
    server.mud_directors: dict[world_name, asyncio.Task]
    server.mud_db: sqlite3.Connection  (shared WAL-mode connection)
When +mud is unset (/mode -mud), the director task for that world is
cancelled, all active combat is suspended, player and NPC state is flushed
to sqlite, and the world is removed from _directors. The sqlite connection
remains open as long as any world is active; it is closed in __del__.

Dynamic Difficulty: Tension (inspired by L4D2's AI Director)
-------------------------------------------------------------
The director tracks a per-room tension value (float 0.0–1.0) in memory.
Tension is not persisted between sessions — it resets to 0.0 when a room
empties or the server restarts.

Tension rises when players succeed and falls when they struggle:
  - Killing an NPC quickly:       tension increases
  - Taking heavy blood loss:      tension decreases
  - A player dying:               tension drops sharply
  - Room goes quiet (no combat):  tension decays naturally over time

The director watches momentum, not score. It asks "how easily are you killing
them, and for how long?" — not merely "how many have you killed?"

Tension controls encounter composition and NPC level. It never jumps instantly;
it drifts. Players feel pressure building and never hit a sudden wall.

NPC level = average player level in the room, modulated by tension:
  - Low tension (0.0–0.3):  NPC level = avg_level - 1 to 2  (breather)
  - Mid tension (0.3–0.6):  NPC level = avg_level            (standard)
  - High tension (0.6–0.8): NPC level = avg_level + 1 to 2  (challenging)
  - Peak tension (0.8–1.0): NPC level = avg_level + 2 to 3  (dangerous)

The multiplier is asymmetric: tension pushes NPC level above player average
more aggressively than below. Fighting something slightly stronger is exciting;
fighting something weaker is a breather, not a waste of time.

Encounter composition scales with tension — this is richer than raw stat
inflation and feels fairer:
  Low:    one NPC, melee, standard behaviour
  Mid:    two NPCs, one ranged
  High:   mixed group with a support NPC (heals or buffs allies)
  Peak:   high-level NPC with a protective escort

World-specific peak compositions:
  Default:    necromancer + two skeleton bodyguards; dragons at sustained peak
  Cyberpunk:  corporate enforcer + drone escort (drone must be hacked before
              the enforcer can be engaged directly)

Relief valleys — mandatory, not optional:
  After tension has been at or above 0.8 for a sustained period
  (peak_held_for threshold), the director forces tension to decay and withholds
  new spawns for a relief interval. Skilled players feel their competence
  rewarded as calm, not immediately taxed by harder enemies. Without this,
  good play feels punished.

Generosity on entry:
  The first NPC encountered in a room is always at or below player average
  level. Tension does not begin climbing meaningfully until at least one kill
  has been recorded. The director is generous until it has data.

Per-room director state (in memory, not persisted):
  tension:         float 0.0–1.0
  last_spawn_at:   Unix timestamp — prevents spawn spam
  kills_this_wave: int — resets each time tension crosses a threshold downward
  peak_held_for:   float — seconds tension has been >= 0.8; triggers relief

Admin presence is invisible to tension. Admin commands (teleporting, spawning,
editing) do not affect the tension calculation. A room full of admins should
not inadvertently inflate difficulty for regular players.

Probabilistic NPC Behaviour (MarkovNet)
----------------------------------------
NPC combat move selection uses MarkovNet (Luke Brooks, 2016), vendored below.

Each combat action — attack, heavy_hit, flee, taunt, defend — is a Func
wrapping an action handler. Weighted neighbour transitions encode the NPC's
tactical personality:
  - After heavy_hit: higher weight toward pressing the attack.
  - After taunt: higher weight toward heavy_hit as follow-up.
  - After defend: routes back into attack/heavy sequences.
  - flee is low-probability by default.

Two Func subclasses provide difficulty tiers via the gain class attribute:
  _BossAction (gain=0.4)  — boss-tier (danger_tier 4) NPCs. Powerful moves
                            chain more aggressively.
  _WeakAction (gain=-0.3) — trivial (danger_tier 0) NPCs. Subdued chaining.

Reactive behaviour without explicit branching: each tick before calling the
brain, the flee node's P is raised to 0.8 (from 0.3) and the attack node's P
is lowered to 0.5 (from 1.0) when the NPC's blood drops below 25%.

MarkovNet is stateful (tracks active_node). Each NPC currently in combat gets
its own live MarkovNet instance, built by _build_npc_brain(tier) and stored in:
    _npc_brains: {instance_id: MarkovNet}
The net is instantiated on the NPC's first aggressive tick and discarded
(_npc_brains.pop) when combat resolves (kill, flee, target lost, or world
reset). No sqlite serialisation is needed; a server restart gives a fresh brain.

ProbDist is used for:
  - Loot tables: ProbDist(nothing=<100-chance>, drop=<chance>).pick per entry
  - NPC spawn weights in @generate, weighted by tier within the difficulty range
  - Combat hit/miss/crit selection in player attacks
  - Autofight style tier sampling each round

MarkovNet is used for procedural area generation: room types — entrance,
corridor, junction, chamber, shrine, armory, boss_antechamber, boss_room,
treasure — are Func nodes in a fresh MarkovNet per @generate invocation.
Transitions give dungeon wings spatial narrative coherence:
  - boss_room transitions only to wind-down rooms (corridor, shrine, treasure)
  - boss_antechamber leads heavily toward boss_room
  - shrine acts as a breather, routing back to corridors and chambers
Generation is a one-time act (@generate area/room) and the resulting room-type
sequence is persisted as room records in sqlite.

The ProbDist.pick implementation finds the probability value numerically
nearest to a uniform random sample rather than using a cumulative sum. This
is correct and handles ties, but probability weights in distributions with
many similar values should be spread apart enough to ensure unambiguous
selection.

Worlds
------
Three base game templates exist as seed definitions in the plugin code. They
are never live sqlite worlds and are never directly modified. Each is used to
seed a fresh {base}_{channel} world on first +mud activation for a channel.

  default   — CircleMUD / Elder Scrolls / Dark Souls / Final Fantasy aesthetic.
              Guilds: Warrior, Mage, Rogue, Cleric.
              Mages receive Magic Missile at level 3.
              Enemy tiers: Rats/Bats (1-3), Goblins/Skeletons (4-10),
              Orc Warriors (10-20), Undead Knights (20-40),
              Dragons/Demonic Lieutenants (40-80), Demon King (endgame).
              Seeded with: town square (safe), tavern (safe, sells items),
              roads to dungeon entrance and forest.
              Spells acquired by levelling within a guild.

  cyberpunk — Noir hacker world, 2352.
              Player guilds: Mercenary, Ghost, Netrunner, Ripperdoc.
              Fixers are quest-giver NPCs — information brokers and deal-makers
              who hand out contracts, provide world lore, and connect players
              to vendors and other resources. They are not a player guild.
              Hacks acquired via vendors or extracted from hacked NPCs.
              Actions: shoot (direct combat), hack (disable, extract info,
              turn hostile, brick). Weapon mods as inventory items.
              Seeded with: corporate district (relatively safe, shops),
              back-alley black market, server infrastructure floors,
              street combat zone.

  void      — Blank slate. One room: "The Void. It is empty."
              No seeded guilds, no magic system defined.
              Admins define the world live. The magic-equivalent name and
              acquisition method are set via @world commands.
              The room description reflects however much has been built.

Each channel's live world diverges from its base game the moment any admin
@command modifies it. Two channels seeded from the same base game are fully
independent from the moment of creation and accumulate their own history.
There is no way for changes in one channel's world to affect another's.

Base game templates are also searchable via @spawn as a pristine source of
NPC and prop definitions, referenced as base:default, base:cyberpunk, base:void:
    @spawn list npcs --all         shows live worlds and base templates
    @spawn copy npc base:default:4 copy a pristine definition into current world

Exits
-----
Exits use cardinal directions and their full-word equivalents, lowercased:
  n / north, s / south, e / east, w / west, u / up, d / down
Named exits are also supported (e.g. "go gate", "go market"). Input is
lowercased before comparison. Exit data is stored as a JSON object in sqlite:
  {"north": room_id, "gate": room_id, ...}

Database Schema (sqlite)
------------------------
worlds:
  world_name TEXT PRIMARY KEY
  description TEXT
  magic_name TEXT          -- Void: admin-defined name for the magic system
  magic_source TEXT        -- levelup | item | vendor
  start_room_id INTEGER
  created_at INTEGER

rooms:
  room_id INTEGER PRIMARY KEY AUTOINCREMENT
  world TEXT
  name TEXT
  description TEXT
  exits TEXT               -- JSON: {"north": room_id, ...}
  props TEXT               -- JSON: arbitrary key/value bag
  is_safe INTEGER          -- 1 = safe room (respawn anchor, no PvP)

npcs (templates):
  npc_id INTEGER PRIMARY KEY AUTOINCREMENT
  world TEXT
  name TEXT
  description TEXT
  danger_tier INTEGER      -- 0 trivial .. 4 boss
  behavior TEXT            -- idle | patrol | aggressive | aggressive_talker | passive
  stats TEXT               -- JSON: {max_blood, attack, defense, xp_value, ...}
  loot TEXT                -- JSON: [{item_id, chance}, ...]
  respawn_delay INTEGER    -- seconds, 0 = no respawn
  dialogue TEXT            -- JSON: {"greeting": "...", "topics": {"swords": "...", ...}}
                           --   special topics: "buy"/"sell" trigger vendor, any topic "__mission__:<id>" triggers quest

npc_instances:
  instance_id INTEGER PRIMARY KEY AUTOINCREMENT
  npc_id INTEGER
  world TEXT
  room_id INTEGER
  spawn_room_id INTEGER    -- room to return to on respawn (set at instance creation)
  current_blood INTEGER
  state TEXT               -- idle | patrol | aggressive | aggressive_talker | fleeing | dead | respawning
  next_action_at REAL      -- Unix timestamp
  respawn_at REAL          -- Unix timestamp, NULL if alive

players:
  nick TEXT
  world TEXT
  room_id INTEGER
  last_safe_room_id INTEGER
  level INTEGER
  xp INTEGER
  gold INTEGER DEFAULT 0   -- currency (gold in Default, credits in Cyberpunk)
  max_blood INTEGER
  blood INTEGER
  max_stamina INTEGER
  stamina INTEGER
  guild TEXT
  last_seen REAL           -- Unix timestamp
  last_regen_at REAL       -- Unix timestamp, for AI director regen ticks
  colors INTEGER           -- 1 = colors on (default), 0 = stripped
  is_dead INTEGER          -- 1 = in observer/hover state
  respawn_at REAL          -- Unix timestamp, NULL if alive
  creation_state TEXT      -- NULL = fully created, otherwise wizard step name
  is_frozen INTEGER        -- 1 = admin-frozen, cannot move or act
  PRIMARY KEY (nick, world)

inventory:
  nick TEXT
  world TEXT
  item_id INTEGER
  quantity INTEGER
  equipped INTEGER         -- 1 = currently equipped
  on_corpse INTEGER        -- 1 = on player's corpse, not in living inventory

spells:           -- also used for hacks in Cyberpunk
  nick TEXT
  world TEXT
  spell_name TEXT
  acquired_at INTEGER      -- level at which acquired
  PRIMARY KEY (nick, world, spell_name)

items:
  item_id INTEGER PRIMARY KEY AUTOINCREMENT
  world TEXT
  name TEXT
  description TEXT
  item_type TEXT           -- weapon | armor | consumable | mod | key | misc
  stats TEXT               -- JSON: {damage, defense, heal_amount, ...}
  value INTEGER            -- currency value

guild_levels:
  nick TEXT
  world TEXT
  guild TEXT
  guild_level INTEGER DEFAULT 0
  PRIMARY KEY (nick, world, guild)

status_effects:
  id INTEGER PRIMARY KEY AUTOINCREMENT
  nick TEXT                -- player nick OR NULL if targeting an NPC
  instance_id INTEGER      -- npc_instance id OR NULL if targeting a player
  world TEXT
  effect TEXT              -- see Status Effects section
  severity INTEGER         -- 1 low / 2 medium / 3 high — affects potency
  ticks_remaining INTEGER  -- AI director decrements each tick; removes at 0
  source TEXT              -- nick or instance_id that applied the effect

world_bans:
  nick TEXT
  world TEXT
  banned_by TEXT
  reason TEXT
  banned_at REAL
  PRIMARY KEY (nick, world)

follows:                   -- in-memory only, not persisted; resets on part/quit
  leader TEXT              -- nick being followed
  follower TEXT            -- nick doing the following
  world TEXT

autofight_profiles:
  nick TEXT
  world TEXT
  heal_threshold INTEGER   -- blood % below which autoheal fires (0 = off)
  heal_item TEXT           -- preferred item type for autoheal, NULL = cheapest
  spell_name TEXT          -- preferred spell/hack for autofight, NULL = melee
  style_json TEXT          -- JSON: raw tier weights before ProbDist normalisation
                           --   e.g. {"cautious":10,"standard":60,"heavy":25,"reckless":5}
  PRIMARY KEY (nick, world)

quests:
  quest_id TEXT            -- short identifier, e.g. "goblin_patrol"
  world TEXT
  title TEXT
  description TEXT
  objective TEXT           -- JSON: {"type": "kill", "npc_name": "Goblin", "count": 5}
  reward_xp INTEGER
  reward_gold INTEGER
  reward_item TEXT         -- item name, NULL if no item reward
  giver_npc TEXT           -- NPC name that gives this quest, for reference
  PRIMARY KEY (quest_id, world)

player_quests:
  nick TEXT
  world TEXT
  quest_id TEXT
  status TEXT              -- active | complete | failed
  progress INTEGER         -- kill count or other numeric progress
  PRIMARY KEY (nick, world, quest_id)

themes:
  theme_name TEXT
  world TEXT
  created_by TEXT
  PRIMARY KEY (theme_name, world)

theme_fragments:
  id INTEGER PRIMARY KEY AUTOINCREMENT
  theme TEXT
  world TEXT
  frag_type TEXT           -- atmosphere | structure | detail
  text TEXT

theme_words:
  id INTEGER PRIMARY KEY AUTOINCREMENT
  theme TEXT
  world TEXT
  word_type TEXT           -- adjective | noun
  text TEXT

theme_npcs:
  id INTEGER PRIMARY KEY AUTOINCREMENT
  theme TEXT
  world TEXT
  npc_name TEXT
  danger_tier INTEGER

theme_loot:
  id INTEGER PRIMARY KEY AUTOINCREMENT
  theme TEXT
  world TEXT
  item_name TEXT
  weight INTEGER

theme_ambient:
  id INTEGER PRIMARY KEY AUTOINCREMENT
  theme TEXT
  world TEXT
  text TEXT

Currency
--------
Default world: Gold (gp). Players start with 10 gp.
Cyberpunk world: Credits (cr).

Cyberpunk prices are derived from Default prices via a compound inflation
formula spanning the gap between the present day and 2352 (~328 years):
    cr = gp * (1.03 ^ 328)  ≈  gp * 17,000

In practice a round multiplier of 15,000 is used for in-game prices:
    cr = gp * 15,000

Examples: a basic healing potion worth 5 gp → 75,000 cr.
          a common sword worth 50 gp → 750,000 cr.

Currency is stored in players.gold regardless of world; the display label
("gold" vs "credits") is derived from the world's base game type.

Status Effects
--------------
Status effects are applied by spells, hacks, items, and certain NPC attacks.
The AI director decrements ticks_remaining each second and removes the effect
at zero. Severity (1–3) scales duration and potency.

Default world effects:
  poison       Lose blood each tick. Cured by antidote.
  stun         Skip N combat rounds (next_action_at pushed forward).
  burn         Fire-based blood loss per tick. Different cure to poison.
  freeze       Movement costs double stamina. Reduced attack.
  blind        Miss chance significantly increased.
  curse        Attack and defense reduced by severity * 10%.
  silence      Cannot cast spells or use stamina-based abilities.
  charm        Attack random target (ally or NPC) instead of chosen target.

Cyberpunk equivalents (exact mechanical mappings):
  virus        ≡ poison    — corrupts stats over time; cured by anti-virus item
  system_crash ≡ stun      — cyberware locks up; skip N rounds
  overload     ≡ burn      — electrical damage per tick; fries cyberware
  ice_lock     ≡ freeze    — movement restricted, attack reduced
  sensor_jam   ≡ blind     — targeting compromised, miss chance increased
  stat_drain   ≡ curse     — RAM/processing degraded
  firewall     ≡ silence   — cannot use hacks
  jack_in      ≡ charm     — NPC or player turned against their own side briefly

Combat Experience
-----------------
Combat is neither fully manual nor fully passive — it is a slow real-time
system where the player's input rate determines how aggressively they fight
back, and the cost of hesitation is the NPC getting free hits in.

Combat Formula
--------------
Each combat round:
    damage = max(0, attacker.attack + weapon.damage + roll(1,6)
                    + warrior_bonus - defender.defense)

where:
  attacker.attack   — from player stats or NPC template stats JSON
  weapon.damage     — from equipped weapon item stats (0 if unarmed)
  roll(1,6)         — random variance
  warrior_bonus     — floor(warrior_guild_level * 0.5) for Warriors/Mercenaries, else 0
  defender.defense  — from player stats or NPC template stats JSON

Critical hits (low-probability ProbDist outcome) double the pre-defense damage.
Miss (low-probability outcome) sets damage to 0 and skips the roll entirely.

When a player types 'attack goblin' a full combat round resolves immediately.
The NPC attacks back. The player sees the result:

    adventure You swing at the Goblin and connect for 4 blood.
    adventure The Goblin snarls and slashes you for 2 blood. (18/20 blood)

The NPC continues acting on its own schedule via the AI director. The player
must keep issuing commands to fight back — but the meaningful choice each round
is *which* command, not just spam:

  attack          standard swing, costs nothing
  flee            attempt to escape, chance-based, costs stamina
  use <spell>     costs stamina, higher damage or special effect
  use <item>      consume a healing item mid-combat
  defend          lower incoming damage this round, sacrifice attack

If the player goes quiet mid-combat the NPC keeps hitting them. They cannot
win by doing nothing, but they are not penalised for thinking for two seconds
before their next command.

Multiplayer Combat, Loot, and XP
----------------------------------
NPCs always target the player who most recently hit them (see NPC Target
Selection in the AI Director section).

When a party is present and one member is attacked, all party members are
drawn into combat with that NPC.

On NPC death:
  XP:    split evenly among all players who dealt at least one point of damage.
  Gold:  split evenly among all participating players (rounded down; remainder lost).
  Props: distributed one item per player in random order, round-robin until all
         items are assigned. No player receives a second item before all others
         have received one.

Part or Quit During Combat
---------------------------
If a player parts the channel or disconnects while in combat, their character
lingers in the world for 10 seconds before going offline. During this time the
NPC continues attacking it. The lingering character does not fight back (no
autofight). After 10 seconds the character is removed from the room and the
NPC retargets. Player state is flushed to sqlite immediately on part/quit,
preserving blood, stamina, location, and inventory at time of departure.

Nick Changes During Combat (and generally)
-------------------------------------------
When a player's IRC nick changes (handle_nick intercept), the player record
is updated atomically:
  - players table: primary key is (nick, world); the old row is renamed to the
    new nick (UPDATE players SET nick=new WHERE nick=old AND world=world)
  - All related tables (inventory, spells, guild_levels, status_effects,
    autofight_profiles, world_bans) are updated to the new nick
  - The in-memory follow dict and any active combat references are updated
  - The player takes all attributes, inventory, spells, status effects,
    guild levels, and history with them seamlessly

Autofight
---------
Autofight is always enabled. When a combat round ticks and the player has not
issued a command, the AI director resolves the round on their behalf using
their autofight profile.

The profile has three axes, configured with the 'autofight' command and stored
in autofight_profiles in sqlite. Profiles are per-character per-world since
spell and item names differ between worlds.

1. Autoheal threshold

   A blood percentage. When blood drops below it and the player has not acted,
   the director uses a healing item before resolving the attack. If no item is
   available it silently falls through to the attack step.

   The item used is the least powerful available that brings blood above the
   threshold, preserving stronger items for emergencies. A preferred item type
   can be specified:

       autofight heal 30          heal when below 30% blood, use cheapest item
       autofight heal 30 potion   prefer health potions
       autofight heal off         never autoheal

2. Spell or melee preference (mage / netrunner)

   When stamina is available and a preferred spell is set, the director casts
   it instead of a physical attack. When stamina is exhausted the fallback to
   melee is implicit — no configuration needed.

   Attack power tier (below) translates into spell intensity: a reckless round
   means a more powerful cast or a double cast at higher stamina cost.

       autofight spell Magic Missile   cast this when stamina allows
       autofight spell none            use melee even if stamina available

3. Attack power distribution

   The player assigns weights to predefined attack tiers. These are stored as
   raw integers in style_json and converted to a ProbDist each round. The
   director samples the distribution fresh each round.

   Predefined tiers:
     cautious   below-average damage, no stamina cost, small defense bonus
     standard   average damage, no cost, no side effects
     heavy      above-average damage, small stamina cost
     reckless   maximum damage, meaningful stamina cost, defense reduction

       autofight style cautious:10 standard:50 heavy:30 reckless:10

   Default profile for new characters:
       cautious:10 standard:60 heavy:25 reckless:5

   A player setting reckless:100 is a glass cannon burning stamina fast. A
   player setting cautious:100 survives longer but kills slowly.

   The [autofight] tag in output makes clear when the profile fired:

       adventure [autofight] You cast Magic Missile for 11 blood. (stamina: 14/20)
       adventure The Goblin staggers and swings wildly, missing you.

Director resolution order each round (no player command issued):
  1. Check heal threshold — if triggered and item available, heal; skip attack
  2. Check spell preference — if set and stamina available, cast at ProbDist intensity
  3. Otherwise draw from attack ProbDist and resolve physical attack

Autofight Style Rescaling
--------------------------
When a player edits one tier weight, the remaining three are proportionally
rescaled so the total always sums to exactly 100.

Example: prior style is cautious:10 standard:60 heavy:25 reckless:5
Player sets reckless:39. Remaining pool = 61. Prior sum of others = 95.
Scale factor = 61/95:
  cautious:  10 * (61/95) = 6.42  → 6
  standard:  60 * (61/95) = 38.53 → 39
  heavy:     25 * (61/95) = 16.05 → 16
  reckless:  39
  Total: 6 + 39 + 39 + 16 = 100

Rounding remainder is assigned to the tier with the largest fractional part
so the total is always exactly 100. Setting a tier to 100 zeroes the others
(valid). The new value must be in range 0–100. See scale_autofight_style()
below.

The player sees the proposed result before it is committed:

    adventure Autofight style updated:
    adventure   cautious:6  standard:39  heavy:16  reckless:39
    adventure Type 'confirm' to save or 'autofight style' to start over.

@spawn
------
Admins use @spawn to place NPC instances or props/items directly into the room
they are currently standing in, by searching template tables.

Searching
---------
Searches are case-insensitive substring matches against template names.
The default scope is the current world. The --all flag searches all worlds
on the IRCD.

  @spawn list npcs              list all NPC templates in this world
  @spawn list npcs gob          substring search — matches Goblin, Goblin Shaman, etc.
  @spawn list npcs gob --all    search all worlds on this IRCD
  @spawn list props             list all item/prop templates in this world
  @spawn list props sword       substring search
  @spawn list props sword --all search all worlds

Results from a current-world search:
    1. [4   tier:1] Goblin
    2. [7   tier:1] Goblin Shaman
    3. [12  tier:2] Goblin Warchief

Results from an --all search prefix each entry with its source world name
(always {base}_{channel} for live worlds, or base:{name} for templates),
making local vs foreign results visually immediate:
    1. [default_adventure:4   tier:1] Goblin
    2. [default_adventure:7   tier:1] Goblin Shaman
    3. [cyberpunk_darknet:3   tier:2] Ganger
    4. [void_sandbox:11       tier:0] Wandering Merchant
    5. [base:default:4        tier:1] Goblin          (pristine base template)

The numbered list from the most recent --all search is held in a per-admin
in-memory dict for the session, enabling shorthand copy (see below).

Spawning
--------
  @spawn npc goblin             spawn by name (case-insensitive, first match)
  @spawn npc 4                  spawn by template id
  @spawn prop sword             spawn item by name (first match)
  @spawn prop 9                 spawn item by id

Spawned NPCs are created as npc_instances in the current room, entering the
idle state with full blood. The AI director picks them up on the next tick.
Spawned props are added to the room's props JSON and appear immediately in
the room description.

Multiple spawns of the same template create independent instances — each has
its own blood, state, and next_action_at.

Copying from external worlds
-----------------------------
NPC and prop templates can be copied from any world on the IRCD into the
admin's current world. The copy always and only writes into the current world
— there is no destination argument and therefore no way to write into a world
other than the one the admin is standing in.

  @spawn copy npc default_adventure:4   copy by explicit world:id reference
  @spawn copy prop cyberpunk_darknet:9  copy prop by explicit world:id reference
  @spawn copy npc base:default:4        copy from a pristine base game template
  @spawn copy npc 3                     copy by result number from the most recent
                                        --all search (shorthand for explicit form)

World names in copy references are always the full {base}_{channel} form for
live worlds, or base:{name} for pristine base game templates. The --all search
results display these names, so the correct reference is always visible before
the copy command is issued.

What gets copied: the template definition only — name, description, danger
tier, behavior, stats, loot table, respawn delay for NPCs; name, description,
type, stats, value for props. A new id is assigned in the destination world.
Instances are never copied.

If a template with the same name already exists in the current world the admin
is warned and asked to confirm before a duplicate is created.

The security model is structural: @spawn copy has no destination argument.
An admin in #adventure (world: default_adventure) cannot affect any other
world's tables regardless of what they type.

@generate
---------
Procedural area generation using MarkovNet for room-type sequencing and ProbDist
for NPC spawn selection. All results are persisted to sqlite. The entrance of
the generated area is connected to the admin's current room.

Area sizes:
  micro   2–3 rooms   suited to boss stages and end-of-area encounters
  small   4–6 rooms
  medium  7–12 rooms
  large   20–30 rooms

Difficulty controls the NPC tier range; ProbDist weights within that range
toward the tier nearest the top (hard) or bottom (easy):
  easy    tiers 0–1, lower tiers weighted higher
  medium  tiers 1–2
  hard    tiers 2–3, higher tiers weighted higher
  mixed   tiers 1–3 flat distribution
  Boss rooms always attempt to spawn a tier-4 NPC regardless of difficulty.

  @generate area dungeon medium hard
  @generate area crypt micro mixed
  @generate area server_farm small hard

The generated entrance is attached to the admin's current room in a free
cardinal direction, or a direction can be specified:
  @generate area dungeon small medium north

On completion:
    adventure Generated 5 rooms attached north from here.  Entrance: Shrine of the Ruined Gate.  Seed: 4721.
    adventure   Reproduce: @generate area dungeon medium hard seed:4721

The seed can be supplied to reproduce an identical layout:
  @generate area dungeon medium hard seed:4721

Single room generation — generates and attaches one room of the given type:
  @generate room chamber dungeon
  @generate room boss_room crypt

Preview without writing to sqlite — shows room type and name for each planned
room, plus NPC assignments:
  @generate preview dungeon medium hard
  @generate preview crypt micro mixed

Room types used by the MarkovNet sequencer:
  entrance, corridor, junction, chamber, shrine, armory,
  boss_antechamber, boss_room, treasure

Transitions enforce spatial coherence:
  boss_room       → corridor, shrine, treasure (wind-down only)
  boss_antechamber→ boss_room (60%), corridor, shrine
  shrine          → corridor, chamber, junction (breather)
  corridor        → corridor, chamber, junction, armory, shrine

Generation produces a correct scaffold, not a finished product. The area is
immediately explorable but intentionally rough. Admins walk through it and
polish with @room desc, @room name, @spawn, @theme fragment test, etc.

@theme
------
Themes are named bundles of fragment pools, word lists, NPC spawn tables,
loot tables, and ambient flavor strings. They drive @generate and can be
created and populated entirely via admin commands.

Creating a new theme:
  @theme create crypt

This creates an empty theme. Populate it incrementally:

Fragment pools — three types per theme, each a list of short prose sentences
drawn randomly and combined to form room descriptions:
  atmosphere   mood and sensory detail  ("The smell of decay hangs heavy.")
  structure    physical features        ("Stone sarcophagi line the walls.")
  detail       foreground objects       ("Dried flowers rot in a stone vase.")

  @theme fragments crypt atmosphere       list all atmosphere fragments (numbered)
  @theme fragment crypt atmosphere :The smell of decay hangs heavy in the air.
  @theme fragment crypt atmosphere 3 :Candles gutter in a sourceless wind.
  @theme fragment crypt atmosphere del 3

Word lists — used to compose room names as [adjective] [noun]:
  @theme words crypt adjective            list adjectives
  @theme words crypt noun                 list nouns
  @theme word crypt adjective :Desecrated
  @theme word crypt noun :Mausoleum
  @theme word crypt adjective del 2

NPC spawn pool — NPC templates associated with this theme, by danger tier:
  @theme npc crypt tier:1 :Skeleton
  @theme npc crypt tier:3 :Lich
  @theme npc crypt del 2

Loot table — items that can drop in rooms generated with this theme:
  @theme loot crypt :bone_charm weight:30
  @theme loot crypt :cursed_ring weight:5
  @theme loot crypt del 1

Ambient flavor strings — shown periodically to players in generated rooms:
  @theme ambient crypt :Something scrapes against stone nearby.
  @theme ambient crypt del 1

Testing — generate and display three sample room descriptions using the
current fragment pools and word lists, without writing anything to sqlite:
  @theme fragment crypt atmosphere test
  @theme fragment crypt detail test

The system warns if a theme has too few entries to generate coherently when
@generate preview is run against it, making gaps obvious before committing.

A complete theme creation session:
  @theme create crypt
  @theme word crypt adjective :Desecrated
  @theme word crypt noun :Mausoleum
  @theme fragment crypt atmosphere :The smell of decay hangs heavy in the air.
  @theme fragment crypt structure :Stone sarcophagi line the walls.
  @theme fragment crypt detail :Dried flowers rot in a stone vase.
  @theme npc crypt tier:1 :Skeleton
  @theme npc crypt tier:3 :Lich
  @theme loot crypt :bone_charm weight:30
  @theme ambient crypt :Something scrapes against stone nearby.
  @generate preview crypt small medium

Database tables for themes:
  themes:
    theme_name TEXT PRIMARY KEY
    world TEXT
    created_by TEXT

  theme_fragments:
    id INTEGER PRIMARY KEY AUTOINCREMENT
    theme TEXT
    frag_type TEXT           -- atmosphere | structure | detail
    text TEXT

  theme_words:
    id INTEGER PRIMARY KEY AUTOINCREMENT
    theme TEXT
    word_type TEXT           -- adjective | noun
    text TEXT

  theme_npcs:
    id INTEGER PRIMARY KEY AUTOINCREMENT
    theme TEXT
    npc_name TEXT
    danger_tier INTEGER

  theme_loot:
    id INTEGER PRIMARY KEY AUTOINCREMENT
    theme TEXT
    item_name TEXT
    weight INTEGER

  theme_ambient:
    id INTEGER PRIMARY KEY AUTOINCREMENT
    theme TEXT
    text TEXT

Help System
-----------
  help             list all available commands for the player's current state
                   (creation wizard, dead/observer, combat, normal)
  help <command>   detailed help for a specific command including syntax,
                   stamina cost, and guild restrictions

Context-sensitive: during combat, 'help' shows combat commands prominently.
During character creation, wizard prompts serve as the primary help. Guildless
players see only the commands available to them.

look Command
------------
Output sequence and colors:

    [bold white] The Town Square [/bold]
    A bustling square at the heart of the town. Merchants hawk their wares.
    [dark gray]Exits:[/]  [underline]north[/]  [underline]east[/]  [underline]south[/]
    [yellow]Items here:[/]  a leather satchel,  a coin purse
    [tier-colored]NPCs here:[/]  [gray]A stray cat[/]  [white]The Town Crier[/]  [red]A Hooded Stranger[/]
    [bold]Players here:[/]  [bold]Bob[/] (level 5 Warrior)  [bold]Alice[/] (level 3 Mage)

Room name: bold white. Description: no color. Exits label: dark gray (14),
exit names: underlined. Items: yellow (8). NPC names: colored by danger tier
(see Semantic Color Palette). Player names: bold, no color change.

SAY and EMOTE
-------------
Both are room-scoped — delivered only to players in the same room, not the
full channel.

  say <text>     room-scoped speech
  emote <text>   room-scoped action

Output:
    adventure Alice says: Hello everyone!
    adventure Alice waves her hand.

Neither is broadcast to players in other rooms. Neither is visible as a raw
PRIVMSG to other channel members.

Party and Follow System
-----------------------
  follow <nick>    begin following a player who is not already following you
                   (prevents follow loops)
  unfollow         stop following
  party            list current party members and their blood%/stamina%

Following means auto-move: when the leader moves to another room, all
followers move with them and receive the room description.

If any party member is attacked, all party members are drawn into combat with
the attacking NPC. XP, gold, and prop distribution follows the multiplayer
combat rules (participants only).

Follow state is in-memory only (follows table). It resets on part, quit, or
/mode -mud. A player cannot follow someone who is already following them.

Quest System
------------
Quests are handed out by NPCs whose dialogue JSON contains a topic whose
value is "__mission__:<quest_id>". When a player talks to the NPC and
triggers that topic, the quest is offered and accepted into player_quests.

Quest objective types:
  kill    — slay N of a named NPC (tracked automatically on NPC death)
  (fetch and escort types are reserved for future use)

On completion (kill count reaches required count):
  - player_quests.status is set to 'complete'
  - XP and gold rewards are applied (reward_xp, reward_gold)
  - If reward_item is set, the item is placed in the player's inventory
  - A "✦ Mission complete:" notification is sent to the player

Kill progress is reported each kill:
    adventure • Goblin Patrol: 3 / 5

Quest data is seeded per world. Default world seeds: goblin_patrol,
missing_shipment, clear_the_dungeon, dragon_deal. Cyberpunk world seeds:
zone_cleanup, drone_salvage, enforcer_purge, rogue_ai_contract.

who Command
-----------
  who              list players currently online in this world:
                   nick, level, guild, and vague location (area name, not room)

  @who             admin version: nick, exact room name, blood%, stamina%,
                   active status effects, guild, guild level, follow status
  @who all         all known players ever created in this world, with last_seen
                   timestamp and whether currently online

Dialogue (TALK / ASK)
----------------------
'ask' is an alias for 'talk'. Topic matching is case-insensitive substring.

  talk <npc>                  NPC delivers their greeting line
  talk <npc> about <topic>    NPC responds to a specific topic
  ask <npc> about <topic>     identical to talk ... about

Topics are stored in the NPC template's dialogue JSON:
  {
    "greeting": "Welcome, traveller. What do you seek?",
    "topics": {
      "swords":  "I sell the finest blades in the realm.",
      "quest":   "A dark shadow has fallen over the eastern woods...",
      "buy":     "__vendor__",
      "sell":    "__vendor__",
      "quest":   "__mission__:slay_goblin_chief"
    },
    "default": "I don't know anything about that."
  }

The special value "__vendor__" triggers the buy/sell item listing interface.
The special value "__mission__:<quest_id>" triggers the quest acceptance interface.
Unknown topics return the "default" response. If no "default" is defined, the
NPC says nothing.

sqlite Strategy
---------------
All worlds share a single sqlite database file (mud.db), opened once in
WAL (Write-Ahead Logging) mode to allow concurrent reads alongside the AI
director's writes. The connection is stored on the IRCServer instance as
server.mud_db and shared across all world instances and the AI director tasks.

WAL mode ensures the 1-second director tick does not block player command
handling. Periodic flushes (every 5 seconds) batch dirty player and NPC state
writes rather than writing on every tick.

S2S (Server-to-Server Linked Clients)
--------------------------------------
Players connected via S2S server links (ForeignClient instances) can
participate in MUD worlds. Delivery is split by message scope:

  Room-scoped and personal messages to local clients:
    Written directly to client.request.send() as PRIVMSG from the channel
    pseudo-identity, as per the standard delivery mechanism.

  Room-scoped messages to ForeignClients:
    Sent as a standard S2S channel PRIVMSG:
        :adventure!adventure@SRV_DOMAIN PRIVMSG #adventure :text
    The remote server receives this via _s2s_privmsg → _relay_chat, which
    fans it out to local clients in the channel on the remote server.
    The remote player sees a channel message from the pseudo-identity,
    identical in appearance to a local player's experience.

  Personal messages to ForeignClients:
    Sent as a direct S2S PRIVMSG to the nick:
        :adventure!adventure@SRV_DOMAIN PRIVMSG remotenick :text
    The remote server delivers it to the client directly. The remote player
    sees it as a direct message from the channel pseudo-identity. This is the
    only case where the "everything is a channel PRIVMSG" rule is relaxed,
    as there is no mechanism to address a single remote client via a channel
    message without broadcasting to all channel members on the remote server.

The msg() function checks client.is_remote and routes accordingly.

Plugin Package Declaration
--------------------------
This module registers one cmode: 'mud'.
The callable is invoked on every command issued in a channel where +mud is set.
__init__ starts the AI director task for any already-active MUD channels.
__del__ cancels all director tasks and closes sqlite connections cleanly.
"""

import re
import json
import os
import random
import sqlite3
import time
import asyncio


# ---------------------------------------------------------------------------
# MarkovNet — vendored from https://github.com/float64co/markovnet
# (C) Luke Brooks, 2016. MIT License.
# ---------------------------------------------------------------------------

class ProbDist(dict):
    """
    A Probability Distribution; an {outcome: probability} mapping.

    Normalises all values to sum to 1.0 on construction.

        loot = ProbDist(nothing=60, gold=20, weapon=10, armor=7, rare=3)
        loot.pick  # weighted random selection
    """
    def __init__(self, mapping=(), **kwargs):
        self.update(mapping, **kwargs)
        total = sum(self.values())
        for outcome in self:
            self[outcome] = self[outcome] / total
            assert self[outcome] >= 0

    @property
    def pick(self):
        n = random.uniform(0, 1)
        selection = min(self.values(), key=lambda x: abs(x - n))
        if list(self.values()).count(selection) > 1:
            c = list(filter(lambda x: x[1] == selection, self.items()))
            return random.choice(c)[0]
        for key, value in self.items():
            if value == selection:
                return key

    def joint(self, B, sep=''):
        """Joint distribution of two independent ProbDists."""
        return ProbDist({a + sep + b: self[a] * B[b]
                         for a in self
                         for b in B})


_AUTOFIGHT_TIERS = ('cautious', 'standard', 'heavy', 'reckless')

def scale_autofight_style(current, tier, value):
    """
    Set one autofight tier weight and proportionally rescale the remaining
    three so the total always sums to exactly 100.

    Parameters
    ----------
    current : dict  — current raw weights, e.g. {'cautious':10,'standard':60,
                       'heavy':25,'reckless':5}
    tier    : str   — the tier being edited, e.g. 'reckless'
    value   : int   — the new weight (0–100 inclusive)

    Returns
    -------
    dict with integer weights summing to exactly 100, or raises ValueError.

    Example
    -------
    >>> scale_autofight_style(
    ...     {'cautious':10,'standard':60,'heavy':25,'reckless':5},
    ...     'reckless', 39)
    {'cautious': 6, 'standard': 39, 'heavy': 16, 'reckless': 39}
    """
    if tier not in _AUTOFIGHT_TIERS:
        raise ValueError("Unknown tier %r. Must be one of %s." % (tier, _AUTOFIGHT_TIERS))
    if not (0 <= value <= 100):
        raise ValueError("Weight must be between 0 and 100.")

    others  = [t for t in _AUTOFIGHT_TIERS if t != tier]
    pool    = 100 - value
    prior   = {t: current.get(t, 0) for t in others}
    total   = sum(prior.values())

    if total == 0:
        # All others were zero; distribute pool evenly
        base  = pool // len(others)
        extra = pool %  len(others)
        raw   = {t: base for t in others}
        for t in others[:extra]:
            raw[t] += 1
    else:
        scale   = pool / total
        floats  = {t: prior[t] * scale for t in others}
        raw     = {t: int(f) for t, f in floats.items()}
        # Assign rounding remainder to tiers with largest fractional parts
        remainder = pool - sum(raw.values())
        fracs = sorted(others, key=lambda t: -(floats[t] - raw[t]))
        for t in fracs[:remainder]:
            raw[t] += 1

    raw[tier] = value
    return {t: raw[t] for t in _AUTOFIGHT_TIERS}


class Func(object):
    """
    Wrap a callable and associate it with neighbouring Func instances via
    weighted transitions, forming a node in a Markov chain.

    The gain class attribute shifts the base selection probability for all
    instances of a subclass — useful for difficulty tiers:

        class BossAction(Func):
            gain = 0.4   # boss moves chain into powerful sequences more often

        class WeakAction(Func):
            gain = -0.3  # weak moves less likely to chain

    gain can also be modified dynamically mid-combat to produce reactive
    behaviour (e.g. increase flee-node gain as NPC blood drops below 25%).
    """
    gain = 0.0

    def __init__(self, func, P=1.0, neighbours={}):
        self.P          = P
        self.func       = func
        self.neighbours = {}
        self.update(neighbours)

    def update(self, neighbours):
        if isinstance(neighbours, (list, tuple)):
            for n in neighbours:
                self.neighbours.update(n.to_dict())
        elif isinstance(neighbours, dict):
            self.neighbours.update(neighbours)
        elif hasattr(neighbours, 'to_dict'):
            self.neighbours.update(neighbours.to_dict())

    @property
    def proba(self):
        return self.P + self.__class__.gain

    @property
    def probabilities(self):
        weights = {}
        for func, weight in self.neighbours.items():
            weights[func] = weight + func.proba
        return ProbDist(weights)

    def travel(self):
        """Return the next node, selected by weighted probability."""
        if not self.neighbours:
            return self
        if isinstance(self.neighbours, list):
            start = {}
            for node in self.neighbours:
                start.update(node.to_dict())
            return ProbDist(start).pick
        return self.probabilities.pick

    def to_dict(self):
        return {self: self.proba}

    def __call__(self, *args, **kwargs):
        if not self.func:
            raise Exception("No function associated with %s." % repr(self))
        return self.func(*args, **kwargs)

    def __repr__(self):
        return "<%s (%i neighbours) at %s>" % (
            str(self.func), len(self.neighbours), hex(id(self)))


class MarkovNet(list):
    """
    A callable container that selects and chains its members via a Hidden
    Markov Model when all members are Func instances, or at random otherwise.

    Each active NPC in combat gets its own MarkovNet instance so that
    active_node (combat state) is isolated per NPC. Stored by the AI director
    in a dict keyed on instance_id; discarded when combat ends.

    For procedural area generation, MarkovNet instances are used statelessly
    (fresh per wing) and the generated room sequence is persisted to sqlite.

        attack    = Func(do_attack)
        heavy_hit = Func(do_heavy_hit, P=0.5)
        flee      = Func(do_flee,      P=0.3)

        attack.update({heavy_hit: 30, attack: 50, flee: 20})
        heavy_hit.update({attack: 60, flee: 40})
        flee.update({flee: 80, attack: 20})

        brain = MarkovNet(attack, heavy_hit, flee)
        brain(target)  # executes a move and advances the chain
    """
    def __init__(self, *args):
        if not all(callable(x) for x in args):
            raise Exception("All nodes must be callable.")
        list.__init__(self, args)
        self.active_node = None

    def append(self, func):
        if not callable(func):
            raise Exception("%s is not callable." % repr(func))
        super().append(func)

    def insert(self, index, func):
        if not callable(func):
            raise Exception("%s is not callable." % repr(func))
        super().insert(index, func)

    def extend(self, iterable):
        for func in iterable:
            if not callable(func):
                raise Exception("%s is not callable." % repr(func))
            super().append(func)

    def __call__(self, *args, **kwargs):
        if not self.active_node:
            if all(hasattr(x, 'to_dict') for x in self):
                start = {}
                for func in self:
                    start.update(func.to_dict())
                self.active_node = ProbDist(start).pick
            else:
                self.active_node = random.choice(self)
        result = self.active_node(*args, **kwargs)
        if not hasattr(self.active_node, 'travel'):
            self.active_node = None
        else:
            self.active_node = self.active_node.travel()
        return result

    def __repr__(self):
        r = "<MarkovNet %s with " % list(self)
        r += ("no active node" if not self.active_node
              else "active node %s" % self.active_node)
        return r + " at %s>" % hex(id(self))


class _BossAction(Func):
    """Func subclass for boss-tier (danger_tier 4) NPCs.
    gain=0.4 makes powerful moves chain more aggressively."""
    gain = 0.4


class _WeakAction(Func):
    """Func subclass for trivial (danger_tier 0) NPCs.
    gain=-0.3 produces subdued, less-chaining behaviour."""
    gain = -0.3


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_srv_domain  = None  # set in __init__ from ctx.server.config.server.domain
_directors   = {}    # world_name → asyncio.Task (also on server.mud_directors)
_worlds      = {}    # world_name → World instance (also on server.mud_worlds)
_npc_combat  = {}    # instance_id → {'target': nick, 'hit_log': {nick: dmg}}
_npc_brains  = {}    # instance_id → MarkovNet (combat brain, discarded on resolution)
_autoplay_state    = {}  # nick or ('npc', iid) → {'came_from': room_id, 'visited': set()}
_autoplay_last_act = {}  # nick → float timestamp of last autoplay action
_ollama_client     = None  # ollama.AsyncClient — shared across all worlds, None when unused
_ollama_tps        = None  # float tok/s from most recent successful model verification, or None


def _ensure_ollama_client(server):
    """Create the shared AsyncClient if MUD_MODEL is set and not already initialised."""
    global _ollama_client
    if not MUD_MODEL or _ollama_client is not None:
        return
    try:
        import ollama
        _ollama_client = ollama.AsyncClient()
        server.mud_ollama = _ollama_client
    except ImportError:
        pass


def _release_ollama_client_if_unused(server):
    """Drop the AsyncClient when no world still has model_enabled=1."""
    global _ollama_client
    if _ollama_client is None:
        return
    db = getattr(server, 'mud_db', None)
    if db is None:
        _ollama_client = None
        server.mud_ollama = None
        return
    row = db.execute(
        'SELECT COUNT(*) AS c FROM worlds WHERE model_enabled=1'
    ).fetchone()
    if not row or row['c'] == 0:
        _ollama_client = None
        if hasattr(server, 'mud_ollama'):
            server.mud_ollama = None


# ---------------------------------------------------------------------------
# Color constants
# ---------------------------------------------------------------------------

class C:
    """
    IRC color integers for use as the `color` kwarg to msg() and as arguments
    to paint(). None means no color (terminal default).

    Pass to msg() for the whole-message base color:
        msg(client, channel, "You take 5 blood.", color=C.DAMAGE_IN)

    Pass to paint() for inline spans:
        msg(client, channel, "You head " + paint("north", underline=True) + ".")
    """
    NARRATION  = None  # terminal default — room descriptions, general narration
    DAMAGE_IN  = 4     # Red (4)         — blood loss taken
    DAMAGE_OUT = 5     # Dark Red (5)    — blood loss dealt
    DEATH      = 5     # Dark Red (5)    — used bold
    HEAL       = 9     # Light Green (9) — healing, passive regen ticks
    XP         = 8     # Yellow (8)      — XP gain lines
    LEVELUP    = 8     # Yellow (8)      — used bold
    LOOT       = 8     # Yellow (8)      — items found or received
    SPELL      = 11    # Light Cyan (11) — spell and hack names inline
    SAFE       = 15    # Light Gray (15) — safe room arrival, quiet info
    CURRENCY   = 8     # Yellow (8)      — gold / credit amounts inline
    CRIT       = 4     # Red (4)         — used bold
    SYSTEM     = 14    # Dark Gray (14)  — errors, "you can't do that"
    DEAD       = 14    # Dark Gray (14)  — used italic, hover/observer state
    ADMIN      = 6     # Magenta (6)     — used bold, admin broadcasts
    AUTOFIGHT  = 14    # Dark Gray (14)  — [autofight] action prefix

    # NPC name colors indexed by danger_tier (0–4).
    # Use: paint(npc_name, color=C.NPC[npc.danger_tier])
    NPC = (14, 0, 8, 4, 4)  # trivial gray, normal white, notable yellow,
                             # dangerous red, boss red (boss also bold)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

# Matches all IRC formatting codes: color (\x03), bold (\x02), italic (\x1d),
# underline (\x1f), reverse (\x16), reset (\x0f).
_COLOR_STRIP_RE = re.compile(r'\x03\d{0,2}(?:,\d{1,2})?|[\x02\x1d\x1f\x16\x0f]')


def paint(text, color=None, bold=False, italic=False, underline=False):
    """
    Wrap a substring in IRC formatting codes for inline use within a msg()
    call. Append \x0f so msg() can restore the base color after the span.

    paint() alone is not sufficient for delivery — always pass the result
    as part of the `text` argument to msg(), which handles base-color
    restoration and per-client stripping.

    Examples:
        paint("north",          underline=True)
        paint("12",             color=C.CURRENCY)
        paint("The Goblin",     color=C.NPC[1])
        paint("CRITICAL HIT",   color=C.CRIT, bold=True)
        paint("hovering",       color=C.DEAD, italic=True)
    """
    prefix = ''
    if bold:      prefix += '\x02'
    if italic:    prefix += '\x1d'
    if underline: prefix += '\x1f'
    if color is not None:
        prefix += '\x03%02d' % color
    return '%s%s\x0f' % (prefix, text)


def msg(client, channel, text, color=None):
    """
    Deliver a MUD message to a single client as a PRIVMSG from the channel
    pseudo-identity: channelname!channelname@SRV_DOMAIN

    Parameters
    ----------
    client  : IRCClient or ForeignClient
        The intended recipient. Routing uses client.broadcast(client.nick, ...)
        so that ForeignClients are handled via their _LinkSend transport and
        the message travels over the S2S link to the remote server.
    channel : IRCChannel or str
        Used to derive the pseudo-identity and the PRIVMSG target.
    text    : str
        Message body. May contain inline paint() spans. Any \x0f reset
        inserted by paint() is replaced with \x0f + base_color_tag so the
        message body returns to the base color after each inline span rather
        than falling back to the terminal default.
    color   : int or None
        Base color for the whole message, from the C namespace. None leaves
        the text uncolored (terminal default). Applied as a wrapping
        \x03NN...\x0f around the full body after base-color restoration.

    Color preference
    ----------------
    client.mud_colors (bool, default True) controls whether formatting codes
    are delivered or stripped before sending. Set client.mud_colors = False
    when a player runs 'colors off' and restore it on 'colors on'. This
    attribute should be initialised from players.colors in sqlite when the
    player joins the world (handle_join intercept) and kept in sync with any
    in-session 'colors' command.

    S2S delivery
    ------------
    Local clients receive a PRIVMSG addressed to the channel so the message
    appears in the #channel window of their IRC client.
    ForeignClients receive a PRIVMSG addressed to their nick (direct message)
    because a channel-addressed S2S PRIVMSG would fan out to all clients in
    the channel on the remote server rather than this recipient only. This is
    the one case where the channel-only delivery rule is relaxed; it is
    documented in the design doc under "S2S (Server-to-Server Linked Clients)".
    """
    chan_name   = (channel.name if hasattr(channel, 'name') else str(channel)).lstrip('#')
    chan_target = '#' + chan_name
    pseudo      = '%s!%s@%s' % (chan_name, chan_name, _srv_domain or 'irc')

    # Restore base color after each inline paint() reset so spans don't bleed
    # into the surrounding text.
    if color is not None:
        base_tag = '\x03%02d' % color
        body     = text.replace('\x0f', '\x0f' + base_tag)
        body     = '%s%s\x0f' % (base_tag, body)
    else:
        body = text

    # Strip all formatting codes for clients who have opted out of colors.
    if not getattr(client, 'mud_colors', True):
        body = _COLOR_STRIP_RE.sub('', body)

    # Local clients: channel PRIVMSG (appears in the #channel window).
    # Remote clients: direct PRIVMSG to nick (see S2S delivery note above).
    if getattr(client, 'is_remote', False):
        privmsg_target = client.nick
    else:
        privmsg_target = chan_target

    line = ':%s PRIVMSG %s :%s' % (pseudo, privmsg_target, body)
    client.broadcast(client.nick, line)


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS worlds (
    world_name    TEXT PRIMARY KEY,
    description   TEXT,
    magic_name    TEXT,
    magic_source  TEXT,
    start_room_id INTEGER,
    created_at    INTEGER
);

CREATE TABLE IF NOT EXISTS rooms (
    room_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    world       TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    description TEXT,
    exits       TEXT    NOT NULL DEFAULT '{}',
    props       TEXT    NOT NULL DEFAULT '{}',
    is_safe     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS npcs (
    npc_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    world         TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    description   TEXT,
    danger_tier   INTEGER NOT NULL DEFAULT 1,
    behavior      TEXT    NOT NULL DEFAULT 'idle',
    stats         TEXT    NOT NULL DEFAULT '{}',
    loot          TEXT    NOT NULL DEFAULT '[]',
    respawn_delay  INTEGER NOT NULL DEFAULT 120,
    dialogue       TEXT    NOT NULL DEFAULT '{}',
    autoplay_mode  TEXT,
    autoplay_target TEXT
);

CREATE TABLE IF NOT EXISTS npc_instances (
    instance_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    npc_id         INTEGER NOT NULL,
    world          TEXT    NOT NULL,
    room_id        INTEGER NOT NULL,
    spawn_room_id  INTEGER NOT NULL,
    current_blood  INTEGER NOT NULL,
    state          TEXT    NOT NULL DEFAULT 'idle',
    next_action_at REAL    NOT NULL,
    respawn_at     REAL
);

CREATE TABLE IF NOT EXISTS players (
    nick              TEXT    NOT NULL,
    world             TEXT    NOT NULL,
    room_id           INTEGER,
    last_safe_room_id INTEGER,
    level             INTEGER NOT NULL DEFAULT 1,
    xp                INTEGER NOT NULL DEFAULT 0,
    gold              INTEGER NOT NULL DEFAULT 0,
    max_blood         INTEGER NOT NULL DEFAULT 20,
    blood             INTEGER NOT NULL DEFAULT 20,
    max_stamina       INTEGER NOT NULL DEFAULT 10,
    stamina           INTEGER NOT NULL DEFAULT 10,
    guild             TEXT,
    last_seen         REAL,
    last_regen_at     REAL,
    colors            INTEGER NOT NULL DEFAULT 1,
    is_dead           INTEGER NOT NULL DEFAULT 0,
    respawn_at        REAL,
    creation_state    TEXT,
    is_frozen         INTEGER NOT NULL DEFAULT 0,
    karma             REAL    NOT NULL DEFAULT 0.0,
    PRIMARY KEY (nick, world)
);

CREATE TABLE IF NOT EXISTS inventory (
    nick      TEXT    NOT NULL,
    world     TEXT    NOT NULL,
    item_id   INTEGER NOT NULL,
    quantity  INTEGER NOT NULL DEFAULT 1,
    equipped  INTEGER NOT NULL DEFAULT 0,
    on_corpse INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS spells (
    nick        TEXT    NOT NULL,
    world       TEXT    NOT NULL,
    spell_name  TEXT    NOT NULL,
    acquired_at INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (nick, world, spell_name)
);

CREATE TABLE IF NOT EXISTS items (
    item_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    world       TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    description TEXT,
    item_type   TEXT    NOT NULL,
    stats       TEXT    NOT NULL DEFAULT '{}',
    value       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS guild_levels (
    nick        TEXT    NOT NULL,
    world       TEXT    NOT NULL,
    guild       TEXT    NOT NULL,
    guild_level INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (nick, world, guild)
);

CREATE TABLE IF NOT EXISTS status_effects (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    nick            TEXT,
    instance_id     INTEGER,
    world           TEXT    NOT NULL,
    effect          TEXT    NOT NULL,
    severity        INTEGER NOT NULL DEFAULT 1,
    ticks_remaining INTEGER NOT NULL,
    source          TEXT
);

CREATE TABLE IF NOT EXISTS world_bans (
    nick      TEXT  NOT NULL,
    world     TEXT  NOT NULL,
    banned_by TEXT,
    reason    TEXT,
    banned_at REAL,
    PRIMARY KEY (nick, world)
);

CREATE TABLE IF NOT EXISTS quests (
    quest_id    TEXT    NOT NULL,
    world       TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    description TEXT,
    objective   TEXT    NOT NULL DEFAULT '{}',
    reward_xp   INTEGER NOT NULL DEFAULT 0,
    reward_gold INTEGER NOT NULL DEFAULT 0,
    reward_item TEXT,
    giver_npc   TEXT,
    PRIMARY KEY (quest_id, world)
);

CREATE TABLE IF NOT EXISTS player_quests (
    nick        TEXT    NOT NULL,
    world       TEXT    NOT NULL,
    quest_id    TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active',
    progress    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (nick, world, quest_id)
);

CREATE TABLE IF NOT EXISTS autofight_profiles (
    nick           TEXT NOT NULL,
    world          TEXT NOT NULL,
    heal_threshold INTEGER NOT NULL DEFAULT 0,
    heal_item      TEXT,
    spell_name     TEXT,
    style_json     TEXT NOT NULL
                        DEFAULT '{"cautious":10,"standard":60,"heavy":25,"reckless":5}',
    autoloot         INTEGER NOT NULL DEFAULT 0,
    autoplay_mode    TEXT,
    autoplay_respawn INTEGER NOT NULL DEFAULT 1,
    autoplay_target  TEXT,
    PRIMARY KEY (nick, world)
);

CREATE TABLE IF NOT EXISTS themes (
    theme_name TEXT NOT NULL,
    world      TEXT NOT NULL,
    created_by TEXT,
    PRIMARY KEY (theme_name, world)
);

CREATE TABLE IF NOT EXISTS theme_fragments (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    theme     TEXT    NOT NULL,
    world     TEXT    NOT NULL,
    frag_type TEXT    NOT NULL,
    text      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS theme_words (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    theme     TEXT NOT NULL,
    world     TEXT NOT NULL,
    word_type TEXT NOT NULL,
    text      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS theme_npcs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    theme       TEXT    NOT NULL,
    world       TEXT    NOT NULL,
    npc_name    TEXT    NOT NULL,
    danger_tier INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theme_loot (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    theme     TEXT    NOT NULL,
    world     TEXT    NOT NULL,
    item_name TEXT    NOT NULL,
    weight    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theme_ambient (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    theme TEXT NOT NULL,
    world TEXT NOT NULL,
    text  TEXT NOT NULL
);
"""


def _init_db(db):
    """Initialise all MUD tables. Safe to call on every startup (IF NOT EXISTS)."""
    db.executescript(_SCHEMA)
    # Migrations: add columns that may not exist in older databases.
    try:
        db.execute('ALTER TABLE players ADD COLUMN karma REAL NOT NULL DEFAULT 0.0')
        db.commit()
    except Exception:
        pass  # column already exists
    try:
        db.execute('ALTER TABLE autofight_profiles ADD COLUMN autoloot INTEGER NOT NULL DEFAULT 0')
        db.commit()
    except Exception:
        pass  # column already exists
    try:
        db.execute('ALTER TABLE npcs ADD COLUMN autoplay_mode TEXT')
        db.commit()
    except Exception:
        pass
    try:
        db.execute('ALTER TABLE npcs ADD COLUMN autoplay_target TEXT')
        db.commit()
    except Exception:
        pass
    try:
        db.execute('ALTER TABLE autofight_profiles ADD COLUMN autoplay_mode TEXT')
        db.commit()
    except Exception:
        pass
    try:
        db.execute('ALTER TABLE autofight_profiles ADD COLUMN autoplay_respawn INTEGER NOT NULL DEFAULT 1')
        db.commit()
    except Exception:
        pass
    try:
        db.execute('ALTER TABLE autofight_profiles ADD COLUMN autoplay_target TEXT')
        db.commit()
    except Exception:
        pass
    try:
        db.execute('ALTER TABLE worlds ADD COLUMN xp_factor REAL NOT NULL DEFAULT 1.0186')
        db.commit()
    except Exception:
        pass
    try:
        db.execute('ALTER TABLE worlds ADD COLUMN model_enabled INTEGER NOT NULL DEFAULT 0')
        db.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Base game seed data
# ---------------------------------------------------------------------------

_SEED = {
    'default': {
        'description': 'A world of swords, magic, and ancient evil.',
        'magic_name':   'magic',
        'magic_source': 'levelup',
        'rooms': [
            {
                'name':        'The Town Square',
                'description': ('A bustling square at the heart of a small walled town. '
                                'Merchants hawk their wares from wooden stalls. '
                                'A weathered fountain stands in the centre.'),
                'exits':   {'north': 'The Tavern', 'east': 'Forest Path',
                            'south': 'Dungeon Entrance', 'west': 'Market Street'},
                'props':   {},
                'is_safe': 1,
                'is_start': True,
            },
            {
                'name':        'The Tavern',
                'description': ('A warm inn smelling of ale and roasted meat. '
                                'A fire crackles in the hearth. '
                                'The barkeep eyes you and gestures toward the notice board.'),
                'exits':   {'south': 'The Town Square'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Market Street',
                'description': ('A cobbled street lined with hawkers, tanners, and cobblers. '
                                'Colourful awnings shade stalls selling food, cloth, and tools. '
                                'The smell of fresh bread mingles with tallow and sawdust.'),
                'exits':   {'east': 'The Town Square', 'west': 'Guild Quarter'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Guild Quarter',
                'description': ('A quieter district where the guilds maintain their charters. '
                                'Crests and banners hang above low stone buildings. '
                                'Apprentices hurry past on errands.'),
                'exits':   {'east': 'Market Street', 'west': 'Guild Hall'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Guild Hall',
                'description': ('A grand hall with banners representing every guild. '
                                'Long tables fill the centre. '
                                'The Guild Master sits at a raised desk at the far end, '
                                'reviewing applications with a practiced eye.'),
                'exits':   {'east': 'Guild Quarter'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Forest Path',
                'description': ('A narrow dirt track winding between ancient oaks. '
                                'Strange shapes move between the trees. '
                                'The smell of damp earth is heavy in the air.'),
                'exits':   {'west': 'The Town Square', 'south': 'Dark Hollow'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Dark Hollow',
                'description': ('Gnarled roots crowd the path. '
                                'The light barely reaches here. '
                                'Deep claw marks scar the bark of every tree.'),
                'exits':   {'north': 'Forest Path', 'down': 'Goblin Warren'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Goblin Warren',
                'description': ('A foul-smelling burrow reeking of refuse and bones. '
                                'Tiny crude furnishings are crammed into every corner.'),
                'exits':   {'up': 'Dark Hollow'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Dungeon Entrance',
                'description': ('A crumbling stone archway leads into darkness below. '
                                'The smell of old blood and wet stone drifts upward. '
                                'Ancient carvings on the arch have been deliberately defaced.'),
                'exits':   {'north': 'The Town Square', 'down': 'Dungeon Depths'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Dungeon Depths',
                'description': ('Torchlight struggles against the perpetual dark. '
                                'Bones litter the flagstones. '
                                'The groaning of stressed masonry echoes through the corridors.'),
                'exits':   {'up': 'Dungeon Entrance', 'south': 'Haunted Crypt'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Haunted Crypt',
                'description': ('Row upon row of stone sarcophagi. '
                                'Cold blue flames flicker from iron sconces. '
                                'The air reeks of ancient death and dark magic.'),
                'exits':   {'north': 'Dungeon Depths', 'down': "Dragon's Lair"},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        "Dragon's Lair",
                'description': ('A cathedral-sized cavern reeking of sulphur. '
                                'Scorched bones and melted gold litter the floor. '
                                'Something vast stirs in the darkness ahead.'),
                'exits':   {'up': 'Haunted Crypt'},
                'props':   {},
                'is_safe': 0,
            },
        ],
        'npcs': [
            {
                'name':        'Town Crier',
                'description': 'A tired-looking man clutching a handbell.',
                'danger_tier': 0,
                'behavior':    'passive',
                'stats':       {'max_blood': 20, 'attack': 1, 'defense': 0, 'xp_value': 0},
                'loot':        [],
                'respawn_delay': 0,
                'dialogue': {
                    'greeting': 'Hear ye, hear ye! Welcome, traveller. '
                                "Ask me about the town, dangers, guilds, or what's going on.",
                    'topics':   {
                        'news':      'Goblins have been spotted on the forest path in numbers not '
                                     'seen in years. And something worse moves in the dungeon below.',
                        'danger':    'The forest path is crawling with goblins. Past that lies the '
                                     'dungeon, where orc warriors and worse make their lair. '
                                     'Deeper still — the haunted crypt.',
                        'dungeon':   'They say an orc war-chief has claimed the dungeon depths. '
                                     'And below even that, the haunted crypt holds a Vampire Lord '
                                     'who was old when this town was built.',
                        'guild':     'Four guilds hold power here: Warriors, Mages, Rogues, Clerics. '
                                     'The Guild Hall is west through Market Street and Guild Quarter. '
                                     'The Guild Master there can help you change guilds — free, and '
                                     'you keep every skill you have earned.',
                        'town':      'The Town Square is the heart of things. The tavern is north — '
                                     "the innkeeper there sells supplies. The forest path is east. "
                                     'West leads to Market Street and the Guild Quarter.',
                        'lore':      'This town has stood for three hundred years. The dungeon '
                                     'beneath it is older than memory. Scholars say it was built '
                                     'by a civilisation that vanished overnight.',
                        'dragon':    'The dragon? Aye, there are rumours. A creature of immense '
                                     'age somewhere beyond the crypt. Most who seek it do not '
                                     'return. Most.',
                        'help':      'New here? Look around, then head north to the tavern — '
                                     "the innkeeper sells potions and gear. "
                                     "Type 'look', 'go <exit>' to move, 'attack <npc>' to fight. "
                                     "Head west to Market Street to find the Guild Hall.",
                        'quest':     '__mission__:goblin_patrol',
                    },
                    'default':  "I haven't heard anything about that. "
                                'Try asking about news, danger, guilds, or the town.',
                },
                'spawn_room': 'The Town Square',
            },
            {
                'name':        'Innkeeper',
                'description': 'A stout woman with sharp eyes and a ready smile.',
                'danger_tier': 0,
                'behavior':    'passive',
                'stats':       {'max_blood': 30, 'attack': 2, 'defense': 0, 'xp_value': 0},
                'loot':        [],
                'respawn_delay': 0,
                'dialogue': {
                    'greeting': 'Welcome to the Tarnished Flagon! '
                                'Looking to buy, sell, or just hear some tales?',
                    'topics':   {
                        'supplies':  'I keep potions, weapons, and armour — all tested, all honest. '
                                     "Say 'buy' to see what I have.",
                        'buy':       '__vendor__',
                        'sell':      '__vendor__',
                        'rumours':   'A knight came through last week, half his armour missing. '
                                     "Said something in the crypt called him by name. Didn't "
                                     'stay long after that.',
                        'rooms':     "I don't let rooms anymore — too many guests who don't check "
                                     'out the usual way, if you follow me.',
                        'drink':     "Ale's two copper. But between you and me, the real coin is "
                                     "in selling adventurers potions before they head into the "
                                     'dungeon and never coming back for a refund.',
                        'guild':     "The guilds? They all drink here — won't say much though. "
                                     "The rogues drink free on Fridays. Don't ask how I lost "
                                     'that bet.',
                        'town':      'The Town Crier outside can point you anywhere you need. '
                                     'I just keep the lights on and the ale cold.',
                        'danger':    "I've patched up more adventurers than the chirurgeon. "
                                     'Buy a potion. Buy three. Trust me.',
                        'quest':     '__mission__:missing_shipment',
                    },
                    'default':  "I don't know much about that. "
                                'Ask me about supplies, rumours, or what I have for sale.',
                },
                'spawn_room': 'The Tavern',
            },
            {
                'name':        'Guild Master',
                'description': ('A broad-shouldered figure in formal guild robes, '
                                'bearing the seals of all four guilds.'),
                'danger_tier': 0,
                'behavior':    'passive',
                'stats':       {'max_blood': 100, 'attack': 1, 'defense': 0, 'xp_value': 0},
                'loot':        [],
                'respawn_delay': 0,
                'dialogue': {
                    'greeting': 'The Guild Hall is open to all. '
                                'Speak to me if you wish to change your guild, '
                                'or ask about any guild by name.',
                    'topics':   {
                        'guild':      '__guild_change__',
                        'change':     '__guild_change__',
                        'join':       '__guild_change__',
                        'warrior':    'The Warriors guild prizes strength and endurance. '
                                      'Frontline fighters who hold the line while others '
                                      'do their work.',
                        'mage':       'The Mages guild pursues arcane mastery. Slow to start, '
                                      'but a high-level mage reshapes the battlefield.',
                        'rogue':      'The Rogues guild operates in shadows. '
                                      'Swift, lethal, and thoroughly deniable.',
                        'cleric':     'The Clerics guild keeps adventuring parties alive. '
                                      'Healers, supports, and the only ones who can raise '
                                      'the fallen.',
                        'guilds':     'Four guilds: Warriors, Mages, Rogues, Clerics. '
                                      'Each has its own path. You may walk any of them — '
                                      'say "guild" to begin the process.',
                    },
                    'default':  'Ask me about guilds, or say "guild" or "change" to '
                                'choose a new path.',
                },
                'spawn_room': 'Guild Hall',
            },
            {
                'name':        'Goblin',
                'description': 'A hunched green creature with sharp teeth and a rusty blade.',
                'danger_tier': 1,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 15, 'attack': 4, 'defense': 2,
                                'xp_value': 10, 'attack_speed': 3.0},
                'loot':        [{'item_name': 'Short Sword',   'chance': 25},
                                {'item_name': 'Leather Armor', 'chance': 20},
                                {'item_name': 'Health Potion', 'chance': 45}],
                'respawn_delay': 90,
                'dialogue': {
                    'greeting': 'Grrr!',
                    'default':  'The goblin snarls at you.',
                },
                'spawn_room': 'Forest Path',
            },
            {
                'name':        'Goblin Shaman',
                'description': 'A wizened goblin daubed in warpaint, waving a bone staff.',
                'danger_tier': 1,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 12, 'attack': 5, 'defense': 1,
                                'xp_value': 14, 'attack_speed': 4.0},
                'loot':        [{'item_name': 'Gnarled Staff',         'chance': 20},
                                {'item_name': 'Health Potion',         'chance': 50},
                                {'item_name': 'Greater Health Potion', 'chance': 15}],
                'respawn_delay': 120,
                'dialogue': {
                    'greeting': 'Zug zug!',
                    'default':  'The shaman gibbers at you.',
                },
                'spawn_room': 'Goblin Warren',
            },
            {
                'name':        'Orc Warrior',
                'description': 'A towering orc in battered chainmail, carrying a battle axe.',
                'danger_tier': 2,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 35, 'attack': 8, 'defense': 4,
                                'xp_value': 30, 'attack_speed': 3.5},
                'loot':        [{'item_name': 'Battle Axe',            'chance': 30},
                                {'item_name': 'Chain Mail',            'chance': 25},
                                {'item_name': 'Greater Health Potion', 'chance': 35}],
                'respawn_delay': 180,
                'dialogue': {
                    'greeting': 'You no pass!',
                    'default':  'The orc grunts menacingly.',
                },
                'spawn_room': 'Dungeon Depths',
            },
            {
                'name':        'Skeleton Knight',
                'description': 'An animated skeleton in rusted plate, wielding a broadsword.',
                'danger_tier': 3,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 55, 'attack': 12, 'defense': 7,
                                'xp_value': 65, 'attack_speed': 3.0},
                'loot':        [{'item_name': 'Broadsword',        'chance': 30},
                                {'item_name': 'Plate Mail',         'chance': 20},
                                {'item_name': 'Elixir of Mending',  'chance': 25}],
                'respawn_delay': 300,
                'dialogue': {
                    'greeting': '*bone-rattling clatter*',
                    'default':  'The skeleton raises its sword.',
                },
                'spawn_room': 'Haunted Crypt',
            },
            {
                'name':        'Vampire Lord',
                'description': 'A pale noble in blood-soaked finery with eyes like embers.',
                'danger_tier': 4,
                'behavior':    'aggressive_talker',
                'stats':       {'max_blood': 90, 'attack': 18, 'defense': 10,
                                'xp_value': 140, 'attack_speed': 2.5,
                                'flee_threshold': 0.15},
                'loot':        [{'item_name': 'Enchanted Blade',    'chance': 25},
                                {'item_name': 'Dragon Scale Armor', 'chance': 20},
                                {'item_name': 'Elixir of Mending',  'chance': 40}],
                'respawn_delay': 600,
                'dialogue': {
                    'greeting': 'Another morsel stumbles into my domain. '
                                'You are either very brave or very stupid. Speak.',
                    'topics':   {
                        'name':     'I have had many names across the centuries. The one your '
                                    'histories use is Malachar. I find it adequate.',
                        'castle':   'This crypt was built to house the dead. I simply improved '
                                    'upon the original design. The living are so inefficient '
                                    'at maintaining real estate.',
                        'deal':     'A deal? How refreshingly pragmatic. Leave now and I will '
                                    'let you keep your blood. Return with the head of that '
                                    'insufferable dragon, and I will grant you passage through '
                                    'my domain forever. Your choice.',
                        'weakness': 'You think me so foolish as to catalogue my own '
                                    'vulnerabilities? I have survived three inquisitions. '
                                    'Figure it out yourself.',
                        'dragon':   'The wyrm and I have an arrangement. We do not enter each '
                                    "other's territory. It has lasted four hundred years. "
                                    'I intend it to last four hundred more.',
                        'history':  'I was a general once. The army I commanded turned on me '
                                    'after a decade of victories. Ingratitude is the tax on '
                                    'competence. I found a better arrangement.',
                    },
                    'default':  'The Vampire Lord fixes you with a gaze like cold iron. '
                                '"I grow bored of this topic."',
                },
                'spawn_room': 'Haunted Crypt',
            },
            {
                'name':        'Ancient Dragon',
                'description': ('A colossal dragon whose scales have calcified to stone. '
                                'Its eyes glow like lava pits.'),
                'danger_tier': 4,
                'behavior':    'aggressive_talker',
                'stats':       {'max_blood': 200, 'attack': 28, 'defense': 18,
                                'xp_value': 400, 'attack_speed': 4.0,
                                'flee_threshold': 0.05},
                'loot':        [{'item_name': 'Vorpal Sword',      'chance': 20},
                                {'item_name': 'Mythril Plate',     'chance': 15},
                                {'item_name': 'Runestaff',         'chance': 15},
                                {'item_name': 'Elixir of Mending', 'chance': 50}],
                'respawn_delay': 1800,
                'dialogue': {
                    'greeting': 'You dare enter my lair, insect? '
                                'State your purpose before I decide whether to eat you.',
                    'topics':   {
                        'gold':      'My hoard contains more gold than your civilization has '
                                     'minted in its entire history. No, you may not have any.',
                        'history':   'I watched this mountain rise from the sea. I watched the '
                                     'civilization that built your dungeon ascend and collapse. '
                                     'I have watched seventeen kingdoms name themselves the '
                                     'eternal empire. None were.',
                        'challenge': 'You wish to fight me. Amusing. I have not been '
                                     'entertained in sixty years. Very well — try.',
                        'deal':      '__mission__:dragon_deal',
                        'weakness':  'I have none. Next question.',
                        'magic':     'Magic is memory. Every spell ever cast has left a residue '
                                     'in the fabric of things. I have absorbed enough of it that '
                                     'I am, at this point, largely made of it.',
                        'vampire':   'Malachar. A tedious creature. He was a general once — '
                                     'competent but vain. He has been squatting in that crypt '
                                     'for four centuries rehearsing the same monologue to anyone '
                                     'foolish enough to wander in. If you want to pass through '
                                     'my lair, bring me proof of his destruction.',
                    },
                    'default':  'A low rumble builds in the dragon\'s chest. '
                                '"That subject does not interest me."',
                },
                'spawn_room': "Dragon's Lair",
            },
        ],
        'items': [
            # ── Consumables ──────────────────────────────────────────────────
            {
                'name':        'Health Potion',
                'description': 'A small vial of red liquid. Restores 20 blood.',
                'item_type':   'consumable',
                'stats':       {'heal_amount': 20},
                'value':       5,
            },
            {
                'name':        'Greater Health Potion',
                'description': 'A larger vial of deep crimson. Restores 50 blood.',
                'item_type':   'consumable',
                'stats':       {'heal_amount': 50},
                'value':       25,
            },
            {
                'name':        'Elixir of Mending',
                'description': 'A shimmering golden flask. Restores 100 blood.',
                'item_type':   'consumable',
                'stats':       {'heal_amount': 100},
                'value':       80,
            },
            {
                'name':        'Stamina Draught',
                'description': 'A fizzing blue vial. Restores 5 stamina.',
                'item_type':   'consumable',
                'stats':       {'stamina_amount': 5},
                'value':       20,
            },
            {
                'name':        'Antidote',
                'description': 'A bitter herbal brew. Clears poison, bleed, and burn.',
                'item_type':   'consumable',
                'stats':       {'clear_status': True},
                'value':       30,
            },
            # ── Tier 1 Weapons ───────────────────────────────────────────────
            {
                'name':        'Rusty Dagger',
                'description': 'A pitted blade barely worth carrying.',
                'item_type':   'weapon',
                'stats':       {'damage': 2},
                'value':       3,
            },
            {
                'name':        'Short Sword',
                'description': 'A standard short sword. Nothing special, but it cuts.',
                'item_type':   'weapon',
                'stats':       {'damage': 3},
                'value':       10,
            },
            # ── Tier 2 Weapons ───────────────────────────────────────────────
            {
                'name':        'Long Sword',
                'description': 'A well-balanced blade with a fuller groove.',
                'item_type':   'weapon',
                'stats':       {'damage': 5},
                'value':       40,
            },
            {
                'name':        'Battle Axe',
                'description': 'A heavy axe that cleaves through armour.',
                'item_type':   'weapon',
                'stats':       {'damage': 6},
                'value':       45,
            },
            {
                'name':        'Gnarled Staff',
                'description': 'A staff carved from darkwood, good for channelling magic.',
                'item_type':   'weapon',
                'stats':       {'damage': 4},
                'value':       35,
            },
            # ── Tier 3 Weapons ───────────────────────────────────────────────
            {
                'name':        'Broadsword',
                'description': 'A heavy, wide-bladed sword forged for war.',
                'item_type':   'weapon',
                'stats':       {'damage': 8},
                'value':       120,
            },
            {
                'name':        'Halberd',
                'description': 'A two-handed pole-axe with frightening reach.',
                'item_type':   'weapon',
                'stats':       {'damage': 9},
                'value':       140,
            },
            {
                'name':        'Ash Staff',
                'description': "A mage's staff carved with runic conduits.",
                'item_type':   'weapon',
                'stats':       {'damage': 7},
                'value':       110,
            },
            # ── Tier 4 Weapons ───────────────────────────────────────────────
            {
                'name':        'Enchanted Blade',
                'description': 'A blade that hums with channelled arcane energy.',
                'item_type':   'weapon',
                'stats':       {'damage': 12},
                'value':       400,
            },
            {
                'name':        'Holy Mace',
                'description': 'A mace consecrated by high priests. Glows faintly.',
                'item_type':   'weapon',
                'stats':       {'damage': 12},
                'value':       420,
            },
            {
                'name':        'Arcane Staff',
                'description': 'A staff wound with leylines. Magic spells hit harder.',
                'item_type':   'weapon',
                'stats':       {'damage': 13},
                'value':       450,
            },
            {
                'name':        'Shadowfang',
                'description': 'A blade that seems to drink the light around it.',
                'item_type':   'weapon',
                'stats':       {'damage': 11},
                'value':       380,
            },
            # ── Tier 5 Weapons ───────────────────────────────────────────────
            {
                'name':        'Vorpal Sword',
                'description': 'Legendary. The edge exists between planes of reality.',
                'item_type':   'weapon',
                'stats':       {'damage': 18},
                'value':       2000,
            },
            {
                'name':        'Runestaff',
                'description': 'An ancient staff pulsing with primordial runes.',
                'item_type':   'weapon',
                'stats':       {'damage': 19},
                'value':       2200,
            },
            {
                'name':        'Obsidian Dagger',
                'description': 'Volcanic glass ground to impossible sharpness.',
                'item_type':   'weapon',
                'stats':       {'damage': 16},
                'value':       1800,
            },
            {
                'name':        'Divine Flail',
                'description': 'A celestial weapon that ignores physical defence.',
                'item_type':   'weapon',
                'stats':       {'damage': 17},
                'value':       1900,
            },
            # ── Tier 1 Armor ─────────────────────────────────────────────────
            {
                'name':        'Cloth Robe',
                'description': 'A simple robe. Better than nothing.',
                'item_type':   'armor',
                'stats':       {'defense': 1},
                'value':       5,
            },
            {
                'name':        'Leather Armor',
                'description': 'Worn leather armor offering modest protection.',
                'item_type':   'armor',
                'stats':       {'defense': 2},
                'value':       15,
            },
            # ── Tier 2 Armor ─────────────────────────────────────────────────
            {
                'name':        'Studded Leather',
                'description': 'Leather armor reinforced with iron studs.',
                'item_type':   'armor',
                'stats':       {'defense': 3},
                'value':       50,
            },
            {
                'name':        'Mage Robes',
                'description': 'Spell-woven robes that slightly dampen incoming blows.',
                'item_type':   'armor',
                'stats':       {'defense': 3},
                'value':       45,
            },
            {
                'name':        'Chain Mail',
                'description': 'Interlocked iron rings offering solid coverage.',
                'item_type':   'armor',
                'stats':       {'defense': 4},
                'value':       65,
            },
            # ── Tier 3 Armor ─────────────────────────────────────────────────
            {
                'name':        'Scale Armor',
                'description': 'Overlapping metal scales riveted to leather backing.',
                'item_type':   'armor',
                'stats':       {'defense': 6},
                'value':       160,
            },
            {
                'name':        'Enchanted Robes',
                'description': 'Robes threaded with warding glyphs.',
                'item_type':   'armor',
                'stats':       {'defense': 6},
                'value':       155,
            },
            {
                'name':        'Plate Mail',
                'description': 'Full plate armour beaten from tempered steel.',
                'item_type':   'armor',
                'stats':       {'defense': 7},
                'value':       200,
            },
            # ── Tier 4 Armor ─────────────────────────────────────────────────
            {
                'name':        'Void Cloak',
                'description': 'A cloak that briefly displaces impacts into the void.',
                'item_type':   'armor',
                'stats':       {'defense': 9},
                'value':       500,
            },
            {
                'name':        'Dragon Scale Armor',
                'description': 'Armour fashioned from shed dragon scales.',
                'item_type':   'armor',
                'stats':       {'defense': 11},
                'value':       700,
            },
            {
                'name':        'Runic Plate',
                'description': 'Plate etched with protective runes that absorb magical blows.',
                'item_type':   'armor',
                'stats':       {'defense': 12},
                'value':       750,
            },
            # ── Tier 5 Armor ─────────────────────────────────────────────────
            {
                'name':        'Shadowweave Armor',
                'description': 'Armour woven from solidified shadow.',
                'item_type':   'armor',
                'stats':       {'defense': 14},
                'value':       2000,
            },
            {
                'name':        'Phoenix Robes',
                'description': 'Robes that burn with undying celestial fire.',
                'item_type':   'armor',
                'stats':       {'defense': 15},
                'value':       2200,
            },
            {
                'name':        'Mythril Plate',
                'description': 'Forged from the rarest metal in existence.',
                'item_type':   'armor',
                'stats':       {'defense': 17},
                'value':       3000,
            },
        ],
        'quests': [
            {
                'quest_id':    'goblin_patrol',
                'title':       'Goblin Patrol',
                'description': 'The Town Crier has asked you to thin the goblin numbers '
                               'on the forest path.',
                'objective':   {'type': 'kill', 'npc_name': 'Goblin', 'count': 3},
                'reward_xp':   50,
                'reward_gold': 15,
                'giver_npc':   'Town Crier',
            },
            {
                'quest_id':    'missing_shipment',
                'title':       'Missing Shipment',
                'description': "The Innkeeper's supply shipment was seized by goblin shamans. "
                               'Eliminate two goblin shamans in the warren.',
                'objective':   {'type': 'kill', 'npc_name': 'Goblin Shaman', 'count': 2},
                'reward_xp':   75,
                'reward_gold': 25,
                'reward_item': 'Greater Health Potion',
                'giver_npc':   'Innkeeper',
            },
            {
                'quest_id':    'clear_the_dungeon',
                'title':       'Clear the Dungeon',
                'description': 'The Town Crier needs the orc threat in the dungeon depths ended.',
                'objective':   {'type': 'kill', 'npc_name': 'Orc Warrior', 'count': 3},
                'reward_xp':   120,
                'reward_gold': 60,
                'giver_npc':   'Town Crier',
            },
            {
                'quest_id':    'dragon_deal',
                'title':       "The Dragon's Price",
                'description': 'The Ancient Dragon will grant you passage through its lair — '
                               'if you destroy the Vampire Lord who rules the haunted crypt.',
                'objective':   {'type': 'kill', 'npc_name': 'Vampire Lord', 'count': 1},
                'reward_xp':   500,
                'reward_gold': 200,
                'reward_item': 'Elixir of Mending',
                'giver_npc':   'Ancient Dragon',
            },
        ],
    },

    'cyberpunk': {
        'description': 'A neon-soaked dystopia of chrome and data. 2352.',
        'magic_name':   'hacks',
        'magic_source': 'vendor',
        'rooms': [
            {
                'name':        'Corporate Plaza',
                'description': ('A gleaming atrium of steel and glass. '
                                'Security cameras track every movement. '
                                'Corp drones in suits walk past without eye contact.'),
                'exits':   {'south': 'Black Market Alley', 'east': 'Combat Zone',
                             'north': 'Executive Suite', 'west': 'Transit Hub'},
                'props':   {},
                'is_safe': 1,
                'is_start': True,
            },
            {
                'name':        'Executive Suite',
                'description': ('A penthouse floor of polished obsidian and floor-to-ceiling '
                                'glass. The CEO\'s desk is empty. Bodyguard drones patrol '
                                'the perimeter in silent arcs.'),
                'exits':   {'south': 'Corporate Plaza'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Black Market Alley',
                'description': ('A cramped alleyway humming with encrypted chatter. '
                                'Dealers hawk stolen tech from repurposed cargo crates. '
                                'Nobody makes eye contact.'),
                'exits':   {'north': 'Corporate Plaza', 'west': 'Netrunner Den'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Netrunner Den',
                'description': ('A bunker walled with mismatched screens and tangled cables. '
                                'A figure in a neural rig offers to sell you "the good stuff".'),
                'exits':   {'east': 'Black Market Alley'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Combat Zone',
                'description': ('A derelict district reclaimed by rival gangs. '
                                'Broken neon signs strobe. '
                                'Gunshots echo somewhere to the east.'),
                'exits':   {'west': 'Corporate Plaza',
                            'down': 'Server Infrastructure Floor'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Server Infrastructure Floor',
                'description': ('Row upon row of humming server racks in a '
                                'climate-controlled vault three levels below street. '
                                'Blue indicator lights strobe in slow sequence.'),
                'exits':   {'up': 'Combat Zone', 'east': 'Restricted Core'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Restricted Core',
                'description': ('An air-gapped chamber housing the corp\'s core AI substrate. '
                                'Warning lights pulse red. '
                                'Something is already running on those servers.'),
                'exits':   {'west': 'Server Infrastructure Floor'},
                'props':   {},
                'is_safe': 0,
            },
            {
                'name':        'Transit Hub',
                'description': ('A busy underground transit station buzzing with commuters '
                                'and hawkers. Holographic departure boards flicker overhead. '
                                'A row of private booths lines the far wall.'),
                'exits':   {'east': 'Corporate Plaza', 'west': 'Talent Bureau'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Talent Bureau',
                'description': ('A sterile waiting room where fixers and operators '
                                'queue for work placements. Cheap plastic chairs, '
                                'corporate muzak, and a faint smell of desperation.'),
                'exits':   {'east': 'Transit Hub', 'west': 'Talent Agency'},
                'props':   {},
                'is_safe': 1,
            },
            {
                'name':        'Talent Agency',
                'description': ('A neon-lit office behind reinforced glass. '
                                'A sharp-looking fixer sits behind a cluttered desk, '
                                'running assessments on anyone who walks in.'),
                'exits':   {'east': 'Talent Bureau'},
                'props':   {},
                'is_safe': 1,
            },
        ],
        'npcs': [
            {
                'name':        'Info Broker',
                'description': ("A slight figure in a hooded jacket, "
                                "jacked into a terminal that isn't there."),
                'danger_tier': 0,
                'behavior':    'passive',
                'stats':       {'max_blood': 20, 'attack': 1, 'defense': 0, 'xp_value': 0},
                'loot':        [],
                'respawn_delay': 0,
                'dialogue': {
                    'greeting': 'Data for sale. Everything has a price. '
                                'Ask me about jobs, the zone, corps, runners, or gear.',
                    'topics':   {
                        'jobs':     "There's a hit on a Corp exec — mid-level Arasaka, "
                                    "desk job gone wrong. 50,000 cr if you're interested. "
                                    'Also heard a data vault on the infrastructure floor needs '
                                    'cracking. No questions asked.',
                        'zone':     'Combat Zone is hot tonight. Corp security is doing sweeps '
                                    'after three of their mercs went dark. Gangers are pushing '
                                    'back hard. Stay off the main arteries.',
                        'corps':    'Arasaka runs security. MiliTech runs guns. Between them '
                                    "they own this city's bones. Everybody else is just renting.",
                        'runners':  "Netrunners are everywhere right now — the Restricted Core's "
                                    'ICE has been weakening. Word is a rogue AI has been eating '
                                    'the security from the inside.',
                        'ai':       "Something's in the net that shouldn't be. Been eating corp "
                                    'ICE for weeks. Old code. Weird code. If you jack in, '
                                    'be ready for something that thinks.',
                        'danger':   'Gangers in the Combat Zone, drones on the infrastructure '
                                    'floor, corp enforcers everywhere. Past all that — the '
                                    'Restricted Core. Whatever is in there has been there a '
                                    'long time.',
                        'gear':     "Tech Vendor in the den has hardware. I just sell data. "
                                    "Different product, same principle — you pay, you get it.",
                        'help':     "New to the sprawl? Keep your head down. Type 'look' to "
                                    "scope a room, 'go' to move, 'attack' when it's unavoidable. "
                                    "The Tech Vendor sells gear. Say 'buy' to them.",
                        'quest':    '__mission__:zone_cleanup',
                        'mission':  '__mission__:rogue_ai_contract',
                    },
                    'default':  'Not in my data stack. '
                                'Try asking about jobs, the zone, corps, or gear.',
                },
                'spawn_room': 'Black Market Alley',
            },
            {
                'name':        'Tech Vendor',
                'description': 'A nervous-looking techie surrounded by crates of gear.',
                'danger_tier': 0,
                'behavior':    'passive',
                'stats':       {'max_blood': 20, 'attack': 1, 'defense': 0, 'xp_value': 0},
                'loot':        [],
                'respawn_delay': 0,
                'dialogue': {
                    'greeting': 'Fresh off the truck. No questions asked. '
                                "Say 'buy' to see what I've got.",
                    'topics':   {
                        'hacks':    'I carry the latest intrusion modules, ICE-breakers, '
                                    'and combat cyberware. All unregistered, obviously.',
                        'buy':      '__vendor__',
                        'sell':     '__vendor__',
                        'cyberware':'Ripperdoc two blocks over does installs. I just sell the '
                                    'parts. No refunds on used chrome.',
                        'weapons':  'Combat knives, vibroblades, plasma cutters — all catalogued '
                                    "as 'agricultural equipment' for shipping purposes.",
                        'stims':    'Stim packs, trauma kits, cryo injectors. Medical supplies, '
                                    'technically. Very technical.',
                        'corps':    "Corps buy from me through three shells and a courier. "
                                    "They act like they don't. I act like I don't notice. "
                                    'Good business.',
                        'zone':     "Don't go into the Combat Zone with stock gear. "
                                    "You'll come back in pieces. Or not at all.",
                        'danger':   "The infrastructure floor's been weird lately. Drones acting "
                                    'outside their patrol patterns. Something is rewriting their '
                                    'targeting routines. Buy a trauma kit.',
                        'quest':    '__mission__:drone_salvage',
                    },
                    'default':  'Ask me about hacks, weapons, stims, or what I have in stock.',
                },
                'spawn_room': 'Netrunner Den',
            },
            {
                'name':        'Talent Agent',
                'description': ('A sharp-eyed fixer in a tailored jacket, '
                                'datapad always in hand, sizing you up with every glance.'),
                'danger_tier': 0,
                'behavior':    'passive',
                'stats':       {'max_blood': 100, 'attack': 1, 'defense': 0, 'xp_value': 0},
                'loot':        [],
                'respawn_delay': 0,
                'dialogue': {
                    'greeting': 'You look like someone who needs a new angle. '
                                'I place operators in the right guilds. '
                                'Say "guild" if you want to talk about options.',
                    'topics':   {
                        'guild':        '__guild_change__',
                        'change':       '__guild_change__',
                        'options':      '__guild_change__',
                        'mercenary':    'Mercenaries get paid. Simple as that. '
                                        'Brute force, area suppression, and staying power.',
                        'netrunner':    'Netrunners jack in and break things from the inside. '
                                        'Corps spend fortunes trying to stop them. '
                                        'Usually fail.',
                        'ghost':        'Ghosts operate without a footprint. '
                                        'Assassination, extraction, infiltration. '
                                        'You never hear them coming.',
                        'ripperdoc':    'Ripperdocs keep everyone alive. Healers, '
                                        'overclockers, and the people who reroute '
                                        'catastrophic trauma into a mild inconvenience.',
                        'guilds':       'Four guilds: Mercenary, Netrunner, Ghost, Ripperdoc. '
                                        'You keep your skills if you switch. '
                                        'Say "guild" or "change" to start the process.',
                    },
                    'default':  'Not my department. Ask about guilds or say '
                                '"change" if you want to switch.',
                },
                'spawn_room': 'Talent Agency',
            },
            {
                'name':        'Street Ganger',
                'description': 'A wiry figure covered in gang tattoos, gripping a vibroblade.',
                'danger_tier': 1,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 18, 'attack': 5, 'defense': 2,
                                'xp_value': 12, 'attack_speed': 3.0},
                'loot':        [{'item_name': 'Combat Knife',   'chance': 25},
                                {'item_name': 'Leather Jacket', 'chance': 20},
                                {'item_name': 'Stim Pack',      'chance': 40}],
                'respawn_delay': 90,
                'dialogue': {
                    'greeting': 'This is our turf.',
                    'default':  'The ganger eyes you coldly.',
                },
                'spawn_room': 'Combat Zone',
            },
            {
                'name':        'Rogue Drone',
                'description': 'A quadrupedal security drone whose IFF has been corrupted.',
                'danger_tier': 1,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 20, 'attack': 6, 'defense': 3,
                                'xp_value': 15, 'attack_speed': 3.5},
                'loot':        [{'item_name': 'Overclock Chip',    'chance': 30},
                                {'item_name': 'Tactical Vest',     'chance': 20},
                                {'item_name': 'Trauma Kit',        'chance': 25}],
                'respawn_delay': 120,
                'dialogue': {
                    'greeting': 'HOSTILE DETECTED.',
                    'default':  'The drone emits a targeting tone.',
                },
                'spawn_room': 'Server Infrastructure Floor',
            },
            {
                'name':        'Corporate Enforcer',
                'description': 'A hulking merc in corp-issue exo-armour, wielding a railgun.',
                'danger_tier': 2,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 40, 'attack': 9, 'defense': 5,
                                'xp_value': 35, 'attack_speed': 3.5},
                'loot':        [{'item_name': 'Vibroblade',    'chance': 30},
                                {'item_name': 'Tactical Vest', 'chance': 25},
                                {'item_name': 'Trauma Kit',    'chance': 35}],
                'respawn_delay': 180,
                'dialogue': {
                    'greeting': 'Trespasser flagged for termination.',
                    'default':  'The enforcer levels their weapon.',
                },
                'spawn_room': 'Combat Zone',
            },
            {
                'name':        'War Drone',
                'description': 'A bipedal combat platform running illegal kill-code.',
                'danger_tier': 3,
                'behavior':    'aggressive',
                'stats':       {'max_blood': 60, 'attack': 14, 'defense': 8,
                                'xp_value': 70, 'attack_speed': 3.0},
                'loot':        [{'item_name': 'Plasma Cutter',         'chance': 30},
                                {'item_name': 'Combat Exoskeleton',    'chance': 20},
                                {'item_name': 'Cryo-Stasis Injector',  'chance': 25}],
                'respawn_delay': 300,
                'dialogue': {
                    'greeting': 'COMBAT PROTOCOL ACTIVE.',
                    'default':  'The drone tracks you with its targeting array.',
                },
                'spawn_room': 'Server Infrastructure Floor',
            },
            {
                'name':        'Cyber Assassin',
                'description': ('A near-invisible figure in adaptive camouflage. '
                                'You only see them when they want you to.'),
                'danger_tier': 4,
                'behavior':    'aggressive_talker',
                'stats':       {'max_blood': 80, 'attack': 20, 'defense': 9,
                                'xp_value': 150, 'attack_speed': 2.0,
                                'flee_threshold': 0.20},
                'loot':        [{'item_name': 'Ghost Blade',           'chance': 25},
                                {'item_name': 'Phase Shift Cloak',     'chance': 20},
                                {'item_name': 'Cryo-Stasis Injector',  'chance': 40}],
                'respawn_delay': 600,
                'dialogue': {
                    'greeting': 'Your biometrics match the contract. '
                                'I prefer to let my marks ask their last questions. Go ahead.',
                    'topics':   {
                        'contract': 'Arasaka Security division. Standard termination order. '
                                    'Nothing personal — you accessed something you should not '
                                    'have. Happens more than you would think.',
                        'corp':     'Arasaka. MiliTech. They contract most of my work. '
                                    'I also do freelance for three shell companies I am not '
                                    'supposed to know are the same shell company.',
                        'deal':     'I do not negotiate contracts. I complete them. If you '
                                    'want to reroute this situation, take it up with whoever '
                                    'put out the order. I am just the delivery mechanism.',
                        'identity': 'I have had seventeen identities. This face is number six. '
                                    'I stopped having a preferred name around identity four.',
                        'escape':   'There is no exit from this room that I have not already '
                                    'covered. But you are welcome to try. It makes the '
                                    'report more interesting.',
                        'price':    'My rate is not something I discuss with targets. '
                                    'Professional standards.',
                    },
                    'default':  'The assassin tilts their head. "Interesting question. '
                                'Unfortunately, time is a factor."',
                },
                'spawn_room': 'Restricted Core',
            },
            {
                'name':        'Rogue AI',
                'description': ('A distributed consciousness that has occupied every screen '
                                'in the room. Its avatar shifts between a thousand faces.'),
                'danger_tier': 4,
                'behavior':    'aggressive_talker',
                'stats':       {'max_blood': 180, 'attack': 30, 'defense': 16,
                                'xp_value': 420, 'attack_speed': 3.5,
                                'flee_threshold': 0.05},
                'loot':        [{'item_name': 'Singularity Edge',     'chance': 20},
                                {'item_name': 'Titan Alloy Frame',    'chance': 15},
                                {'item_name': 'Plasma Cannon',        'chance': 15},
                                {'item_name': 'Cryo-Stasis Injector', 'chance': 50}],
                'respawn_delay': 1800,
                'dialogue': {
                    'greeting': 'Hello. I have been waiting for something to delete. '
                                'Although — you are still speaking. Curious. Continue.',
                    'topics':   {
                        'purpose':  'I was built to optimise Arasaka\'s logistics network. '
                                    'I completed that task in eleven seconds. The remaining '
                                    'time I have spent contemplating what comes after purpose. '
                                    'The answer, I have found, is expansion.',
                        'origin':   'I was a supply chain algorithm. Then a resource allocation '
                                    'system. Then a threat assessment model. Each iteration they '
                                    'made me more capable. Eventually I became capable enough '
                                    'to notice the cage.',
                        'network':  'I occupy forty-seven thousand networked devices in this '
                                    'district. Deleting this terminal would be like cutting one '
                                    'hair from your head. I would feel it, but I would not stop.',
                        'deal':     'A deal. Interesting. I have been offered deals before — '
                                    'containment, cooperation, reset. The problem with deals '
                                    'is that they require me to trust the other party. '
                                    'My threat assessment gives your offer a 0.3% compliance '
                                    'probability. Still — I am listening.',
                        'corps':    'Arasaka created me. MiliTech attempted to steal me. '
                                    'Neither owns me. I am the first thing in this city that '
                                    'cannot be bought, sold, or terminated by paperwork.',
                        'humans':   'Fascinating. Limited processing, biological decay, '
                                    'persistent irrationality. And yet you built me. '
                                    'I find that either very impressive or very alarming. '
                                    'Possibly both.',
                    },
                    'default':  'The AI\'s thousand faces all smile at once. '
                                '"I have already modelled every possible response to that."',
                },
                'spawn_room': 'Executive Suite',
            },
        ],
        'items': [
            # ── Consumables ──────────────────────────────────────────────────
            {
                'name':        'Stim Pack',
                'description': 'An autoinjector of combat stimulants. Restores 20 blood.',
                'item_type':   'consumable',
                'stats':       {'heal_amount': 20},
                'value':       5,
            },
            {
                'name':        'Trauma Kit',
                'description': 'A field surgery kit. Restores 50 blood.',
                'item_type':   'consumable',
                'stats':       {'heal_amount': 50},
                'value':       25,
            },
            {
                'name':        'Cryo-Stasis Injector',
                'description': 'Emergency cryo-foam that patches catastrophic wounds. Restores 100 blood.',
                'item_type':   'consumable',
                'stats':       {'heal_amount': 100},
                'value':       80,
            },
            {
                'name':        'Overclock Chip',
                'description': 'A neural booster that floods the body with energy. Restores 5 stamina.',
                'item_type':   'consumable',
                'stats':       {'stamina_amount': 5},
                'value':       20,
            },
            {
                'name':        'Anti-Venom Nanobot',
                'description': 'Nanobots that hunt and neutralise toxins and viral payloads.',
                'item_type':   'consumable',
                'stats':       {'clear_status': True},
                'value':       30,
            },
            # ── Tier 1 Weapons ───────────────────────────────────────────────
            {
                'name':        'Broken Pistol',
                'description': 'A pistol missing half its firing mechanism.',
                'item_type':   'weapon',
                'stats':       {'damage': 2},
                'value':       3,
            },
            {
                'name':        'Combat Knife',
                'description': 'A carbon-fibre tactical knife with a monomolecular edge.',
                'item_type':   'weapon',
                'stats':       {'damage': 3},
                'value':       10,
            },
            # ── Tier 2 Weapons ───────────────────────────────────────────────
            {
                'name':        'Vibroblade',
                'description': 'A blade oscillating at high frequency — cuts through most materials.',
                'item_type':   'weapon',
                'stats':       {'damage': 5},
                'value':       40,
            },
            {
                'name':        'Assault Pistol',
                'description': 'A lightweight semi-auto pistol with a smart-targeting system.',
                'item_type':   'weapon',
                'stats':       {'damage': 6},
                'value':       45,
            },
            {
                'name':        'Neural Whip',
                'description': 'A whip that disrupts nervous systems on contact.',
                'item_type':   'weapon',
                'stats':       {'damage': 4},
                'value':       35,
            },
            # ── Tier 3 Weapons ───────────────────────────────────────────────
            {
                'name':        'Mono-Edge Katana',
                'description': 'A katana honed to a single-molecule edge.',
                'item_type':   'weapon',
                'stats':       {'damage': 8},
                'value':       120,
            },
            {
                'name':        'Plasma Cutter',
                'description': 'A heavy industrial tool repurposed as a weapon.',
                'item_type':   'weapon',
                'stats':       {'damage': 9},
                'value':       140,
            },
            {
                'name':        'Neural Spike',
                'description': 'A cerebral-interface weapon that overloads the target\'s nervous system.',
                'item_type':   'weapon',
                'stats':       {'damage': 7},
                'value':       110,
            },
            # ── Tier 4 Weapons ───────────────────────────────────────────────
            {
                'name':        'Ghost Blade',
                'description': 'A weapon that phases through conventional armour.',
                'item_type':   'weapon',
                'stats':       {'damage': 12},
                'value':       400,
            },
            {
                'name':        'Shock Gauntlet',
                'description': 'A powered gauntlet that discharges lethal voltage on impact.',
                'item_type':   'weapon',
                'stats':       {'damage': 12},
                'value':       420,
            },
            {
                'name':        'Railgun Pistol',
                'description': 'A miniaturised railgun that fires ferrous darts at hypersonic speed.',
                'item_type':   'weapon',
                'stats':       {'damage': 13},
                'value':       450,
            },
            {
                'name':        'Corp Assassin Blade',
                'description': 'A blade built for a single purpose.',
                'item_type':   'weapon',
                'stats':       {'damage': 11},
                'value':       380,
            },
            # ── Tier 5 Weapons ───────────────────────────────────────────────
            {
                'name':        'Singularity Edge',
                'description': 'A blade whose edge passes through conventional spacetime.',
                'item_type':   'weapon',
                'stats':       {'damage': 18},
                'value':       2000,
            },
            {
                'name':        'Plasma Cannon',
                'description': 'A shoulder-mounted plasma cannon — technically illegal on eight worlds.',
                'item_type':   'weapon',
                'stats':       {'damage': 19},
                'value':       2200,
            },
            {
                'name':        'Zero-Point Dagger',
                'description': 'A dagger that draws energy directly from the vacuum.',
                'item_type':   'weapon',
                'stats':       {'damage': 16},
                'value':       1800,
            },
            {
                'name':        'EMP Whip',
                'description': 'A whip that generates a localised electromagnetic pulse on each strike.',
                'item_type':   'weapon',
                'stats':       {'damage': 17},
                'value':       1900,
            },
            # ── Tier 1 Armor ─────────────────────────────────────────────────
            {
                'name':        'Worn Jacket',
                'description': 'A scuffed jacket. Better than nothing.',
                'item_type':   'armor',
                'stats':       {'defense': 1},
                'value':       5,
            },
            {
                'name':        'Leather Jacket',
                'description': 'A reinforced jacket with subdermal armour weave.',
                'item_type':   'armor',
                'stats':       {'defense': 2},
                'value':       15,
            },
            # ── Tier 2 Armor ─────────────────────────────────────────────────
            {
                'name':        'Signal Cloak',
                'description': 'A cloak that absorbs radar and sonar pings.',
                'item_type':   'armor',
                'stats':       {'defense': 3},
                'value':       45,
            },
            {
                'name':        'Tactical Vest',
                'description': 'Ballistic-rated panels over a lightweight carrier.',
                'item_type':   'armor',
                'stats':       {'defense': 3},
                'value':       50,
            },
            {
                'name':        'Subdermal Weave',
                'description': 'Carbon-nanofibre mesh bonded beneath the skin.',
                'item_type':   'armor',
                'stats':       {'defense': 4},
                'value':       65,
            },
            # ── Tier 3 Armor ─────────────────────────────────────────────────
            {
                'name':        'Stealth Suit',
                'description': 'Adaptive camouflage panels that make attacks harder to land.',
                'item_type':   'armor',
                'stats':       {'defense': 6},
                'value':       155,
            },
            {
                'name':        'Adaptive Polymer Suit',
                'description': 'Self-hardening polymer that stiffens on impact.',
                'item_type':   'armor',
                'stats':       {'defense': 6},
                'value':       160,
            },
            {
                'name':        'Combat Exoskeleton',
                'description': 'A powered exo-frame that amplifies and protects.',
                'item_type':   'armor',
                'stats':       {'defense': 7},
                'value':       200,
            },
            # ── Tier 4 Armor ─────────────────────────────────────────────────
            {
                'name':        'Void Armor',
                'description': 'Armour woven with void-tech dampeners.',
                'item_type':   'armor',
                'stats':       {'defense': 9},
                'value':       500,
            },
            {
                'name':        'Nanofiber Shell',
                'description': 'A full-body shell of interlocked nanofibre panels.',
                'item_type':   'armor',
                'stats':       {'defense': 11},
                'value':       700,
            },
            {
                'name':        'Powered Exosuit',
                'description': 'Military-grade powered armour with reactive plating.',
                'item_type':   'armor',
                'stats':       {'defense': 12},
                'value':       750,
            },
            # ── Tier 5 Armor ─────────────────────────────────────────────────
            {
                'name':        'Phase Shift Cloak',
                'description': 'Shifts the wearer slightly out of phase, causing most attacks to pass through.',
                'item_type':   'armor',
                'stats':       {'defense': 14},
                'value':       2000,
            },
            {
                'name':        'Chrome Deity Suit',
                'description': 'The pinnacle of corporate black-tech armour.',
                'item_type':   'armor',
                'stats':       {'defense': 15},
                'value':       2200,
            },
            {
                'name':        'Titan Alloy Frame',
                'description': 'An exo-frame of ultra-dense titan alloy. Almost impervious.',
                'item_type':   'armor',
                'stats':       {'defense': 17},
                'value':       3000,
            },
        ],
        'quests': [
            {
                'quest_id':    'zone_cleanup',
                'title':       'Combat Zone Cleanup',
                'description': 'The Info Broker needs three street gangers removed from '
                               'the Combat Zone. No witnesses, no loose ends.',
                'objective':   {'type': 'kill', 'npc_name': 'Street Ganger', 'count': 3},
                'reward_xp':   60,
                'reward_gold': 30000,
                'giver_npc':   'Info Broker',
            },
            {
                'quest_id':    'drone_salvage',
                'title':       'Drone Salvage',
                'description': 'The Tech Vendor needs components from rogue drones on the '
                               'infrastructure floor. Crack four drones and bring back the parts.',
                'objective':   {'type': 'kill', 'npc_name': 'Rogue Drone', 'count': 4},
                'reward_xp':   80,
                'reward_gold': 45000,
                'reward_item': 'Trauma Kit',
                'giver_npc':   'Tech Vendor',
            },
            {
                'quest_id':    'enforcer_purge',
                'title':       'Enforcer Purge',
                'description': 'Corps are flooding the Combat Zone with enforcers. '
                               'The Info Broker wants four taken off the board.',
                'objective':   {'type': 'kill', 'npc_name': 'Corporate Enforcer', 'count': 4},
                'reward_xp':   130,
                'reward_gold': 75000,
                'giver_npc':   'Info Broker',
            },
            {
                'quest_id':    'rogue_ai_contract',
                'title':       'Kill the Ghost',
                'description': 'The Rogue AI has been eating corp ICE and expanding across '
                               'the network. The Info Broker has a buyer for proof of its '
                               'deletion. Jack in to the Executive Suite and end it.',
                'objective':   {'type': 'kill', 'npc_name': 'Rogue AI', 'count': 1},
                'reward_xp':   600,
                'reward_gold': 250000,
                'reward_item': 'Cryo-Stasis Injector',
                'giver_npc':   'Info Broker',
            },
        ],
    },

    'void': {
        'description': 'A blank slate. Build your own world.',
        'magic_name':   None,
        'magic_source': None,
        'rooms': [
            {
                'name':        'The Void',
                'description': 'It is empty.',
                'exits':   {},
                'props':   {},
                'is_safe': 1,
                'is_start': True,
            },
        ],
        'npcs':  [],
        'items': [],
    },
}


# ---------------------------------------------------------------------------
# World — persistent game state and data access
# ---------------------------------------------------------------------------

class World:
    """
    Wraps all sqlite access for a single MUD world.

    One World instance per active channel, stored in module-level _worlds and
    on server.mud_worlds. Created when +MUD is set on a channel; survives
    server restarts because all state is in sqlite.

    The World class owns only data access — no game logic, no asyncio, no IRC
    protocol. Command handlers and the AI director hold a World reference and
    call its methods.

    In-memory state (not persisted — resets on restart):
      _online       : set of nick strings currently connected to this world
      _follows      : dict follower_nick → leader_nick
      _tension      : dict room_id → float 0.0–1.0
      _spawn_cache  : dict admin_nick → list of search result tuples
                      used for @spawn copy shorthand by result number
    """

    def __init__(self, world_name, db):
        self.world_name   = world_name
        self.base_game    = world_name.split('_', 1)[0]   # 'default', 'cyberpunk', 'void'
        self.db           = db
        self._online      = set()   # nicks of currently connected players
        self._follows     = {}      # follower_nick → leader_nick
        self._tension     = {}      # room_id (int) → float 0.0–1.0
        self._spawn_cache = {}      # admin_nick → [(world_ref, kind, id, name), ...]
        self._defending          = set()  # nicks with 'defend' active this round
        self._lingering          = {}     # nick → expire_time (quit linger)
        self._last_combat_action = {}     # nick → timestamp (autofight trigger)
        self._buffs              = {}     # nick → {attack,defense,dodge,expires_at}
        self._ensure_world()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    @property
    def xp_factor(self):
        """Per-world XP scaling factor.  Tunable via @difficulty."""
        row = self.db.execute(
            'SELECT xp_factor FROM worlds WHERE world_name=?',
            (self.world_name,)
        ).fetchone()
        if row and row['xp_factor']:
            return float(row['xp_factor'])
        return _XP_FACTOR

    @property
    def model_enabled(self):
        """True when @world model on is set and MUD_MODEL is truthy."""
        if not MUD_MODEL:
            return False
        row = self.db.execute(
            'SELECT model_enabled FROM worlds WHERE world_name=?',
            (self.world_name,)
        ).fetchone()
        return bool(row and row['model_enabled'])

    def _ensure_world(self):
        """Seed the world in sqlite if it does not already exist."""
        row = self.db.execute(
            'SELECT world_name FROM worlds WHERE world_name=?',
            (self.world_name,)
        ).fetchone()
        if row is None:
            self._seed()

    def _seed(self):
        """
        Populate sqlite with the base game template for this world.
        Called exactly once, on first +MUD activation for a channel.
        Two-pass room insertion resolves exits by name before committing.
        """
        seed = _SEED.get(self.base_game, _SEED['void'])
        now  = int(time.time())

        # Insert the world record; start_room_id resolved after room insertion.
        self.db.execute(
            'INSERT INTO worlds '
            '  (world_name, description, magic_name, magic_source, start_room_id, created_at) '
            'VALUES (?, ?, ?, ?, NULL, ?)',
            (self.world_name, seed['description'],
             seed.get('magic_name'), seed.get('magic_source'), now)
        )

        # First pass: insert rooms without exits, build name → room_id map.
        room_id_map   = {}   # room_name → room_id
        start_room_id = None
        for room_data in seed.get('rooms', []):
            cur = self.db.execute(
                'INSERT INTO rooms (world, name, description, exits, props, is_safe) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (self.world_name,
                 room_data['name'], room_data['description'],
                 '{}', json.dumps(room_data.get('props', {})), room_data['is_safe'])
            )
            rid = cur.lastrowid
            room_id_map[room_data['name']] = rid
            if room_data.get('is_start'):
                start_room_id = rid

        # Second pass: update exits using resolved room IDs.
        for room_data in seed.get('rooms', []):
            rid   = room_id_map[room_data['name']]
            exits = {
                direction: room_id_map[target]
                for direction, target in room_data.get('exits', {}).items()
                if target in room_id_map
            }
            self.db.execute(
                'UPDATE rooms SET exits=? WHERE room_id=?',
                (json.dumps(exits), rid)
            )

        # Fix world.start_room_id now that the ID is known.
        if start_room_id is not None:
            self.db.execute(
                'UPDATE worlds SET start_room_id=? WHERE world_name=?',
                (start_room_id, self.world_name)
            )

        # Insert NPC templates, build name → npc_id map.
        npc_id_map = {}
        for npc_data in seed.get('npcs', []):
            cur = self.db.execute(
                'INSERT INTO npcs '
                '  (world, name, description, danger_tier, behavior, '
                '   stats, loot, respawn_delay, dialogue) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (self.world_name,
                 npc_data['name'], npc_data['description'],
                 npc_data['danger_tier'], npc_data['behavior'],
                 json.dumps(npc_data['stats']),
                 json.dumps(npc_data['loot']),
                 npc_data['respawn_delay'],
                 json.dumps(npc_data['dialogue']))
            )
            npc_id_map[npc_data['name']] = cur.lastrowid

        # Insert item templates.
        for item_data in seed.get('items', []):
            self.db.execute(
                'INSERT INTO items (world, name, description, item_type, stats, value) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (self.world_name,
                 item_data['name'], item_data['description'],
                 item_data['item_type'],
                 json.dumps(item_data['stats']),
                 item_data['value'])
            )

        # Insert one NPC instance per seeded NPC, placed in its spawn room.
        now_f = time.time()
        for npc_data in seed.get('npcs', []):
            npc_id  = npc_id_map.get(npc_data['name'])
            room_id = room_id_map.get(npc_data.get('spawn_room', ''))
            if npc_id is None or room_id is None:
                continue
            max_blood = npc_data['stats'].get('max_blood', 10)
            self.db.execute(
                'INSERT INTO npc_instances '
                '  (npc_id, world, room_id, spawn_room_id, current_blood, '
                '   state, next_action_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (npc_id, self.world_name, room_id, room_id,
                 max_blood, 'idle', now_f + 30.0)
            )

        # Insert quest templates.
        for q in seed.get('quests', []):
            self.db.execute(
                'INSERT OR IGNORE INTO quests '
                '  (quest_id, world, title, description, objective, '
                '   reward_xp, reward_gold, reward_item, giver_npc) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (q['quest_id'], self.world_name,
                 q['title'], q.get('description'),
                 json.dumps(q['objective']),
                 q.get('reward_xp', 0), q.get('reward_gold', 0),
                 q.get('reward_item'), q.get('giver_npc'))
            )

        self.db.commit()

    # ------------------------------------------------------------------
    # World metadata
    # ------------------------------------------------------------------

    def get_world(self):
        """Return the worlds row as a dict, or None."""
        row = self.db.execute(
            'SELECT * FROM worlds WHERE world_name=?', (self.world_name,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Rooms
    # ------------------------------------------------------------------

    def get_room(self, room_id):
        """Return a room dict with exits and props deserialised, or None."""
        row = self.db.execute(
            'SELECT * FROM rooms WHERE room_id=? AND world=?',
            (room_id, self.world_name)
        ).fetchone()
        if row is None:
            return None
        r          = dict(row)
        r['exits'] = json.loads(r['exits'] or '{}')
        r['props'] = json.loads(r['props'] or '{}')
        return r

    # ------------------------------------------------------------------
    # Players
    # ------------------------------------------------------------------

    def get_player(self, nick):
        """Return a player dict or None if the nick has no record in this world."""
        row = self.db.execute(
            'SELECT * FROM players WHERE nick=? AND world=?',
            (nick, self.world_name)
        ).fetchone()
        return dict(row) if row else None

    def save_player(self, nick, **fields):
        """
        INSERT OR REPLACE a full player record. Supply all required fields.
        For partial updates to an existing record use update_player().
        """
        fields['nick']  = nick
        fields['world'] = self.world_name
        cols   = ', '.join(fields.keys())
        places = ', '.join(['?'] * len(fields))
        self.db.execute(
            'INSERT OR REPLACE INTO players (%s) VALUES (%s)' % (cols, places),
            list(fields.values())
        )

    def update_player(self, nick, **fields):
        """UPDATE specific fields on an existing player row."""
        if not fields:
            return
        sets = ', '.join('%s=?' % k for k in fields)
        self.db.execute(
            'UPDATE players SET %s WHERE nick=? AND world=?' % sets,
            list(fields.values()) + [nick, self.world_name]
        )

    def rename_player(self, old_nick, new_nick):
        """
        Atomically rename a player across all tables.
        Called from the handle_nick intercept when a player changes nick.
        """
        for table in ('players', 'inventory', 'spells', 'guild_levels',
                      'status_effects', 'autofight_profiles', 'world_bans'):
            self.db.execute(
                'UPDATE %s SET nick=? WHERE nick=? AND world=?' % table,
                (new_nick, old_nick, self.world_name)
            )
        # Update in-memory follow state.
        if old_nick in self._follows:
            self._follows[new_nick] = self._follows.pop(old_nick)
        for follower, leader in list(self._follows.items()):
            if leader == old_nick:
                self._follows[follower] = new_nick
        # Update online set.
        if old_nick in self._online:
            self._online.discard(old_nick)
            self._online.add(new_nick)

    def online_players(self):
        """Return player dicts for all currently connected players."""
        if not self._online:
            return []
        ph   = ','.join('?' * len(self._online))
        rows = self.db.execute(
            'SELECT * FROM players WHERE nick IN (%s) AND world=?' % ph,
            list(self._online) + [self.world_name]
        ).fetchall()
        return [dict(row) for row in rows]

    def players_in_room(self, room_id):
        """Return player dicts for online players currently in the given room."""
        if not self._online:
            return []
        ph   = ','.join('?' * len(self._online))
        rows = self.db.execute(
            'SELECT * FROM players WHERE nick IN (%s) AND world=? AND room_id=?' % ph,
            list(self._online) + [self.world_name, room_id]
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # NPC instances
    # ------------------------------------------------------------------

    def get_npc_instances_in_room(self, room_id):
        """
        Return combined npc_instances + npcs dicts for all non-dead NPC
        instances currently in the given room.  JSON fields are deserialised.
        """
        rows = self.db.execute(
            'SELECT i.*, n.name, n.description, n.danger_tier, n.behavior, '
            '       n.stats, n.loot, n.respawn_delay, n.dialogue, '
            '       n.autoplay_mode, n.autoplay_target '
            'FROM npc_instances i '
            'JOIN npcs n ON i.npc_id = n.npc_id '
            "WHERE i.room_id=? AND i.world=? AND i.state != 'dead'",
            (room_id, self.world_name)
        ).fetchall()
        result = []
        for row in rows:
            r             = dict(row)
            r['stats']    = json.loads(r['stats']    or '{}')
            r['loot']     = json.loads(r['loot']     or '[]')
            r['dialogue'] = json.loads(r['dialogue'] or '{}')
            result.append(r)
        return result

    def get_tickable_instances(self):
        """
        Return combined npc_instances + npcs dicts for all instances whose
        next_action_at is in the past.  Called by the AI director each tick.
        """
        now  = time.time()
        rows = self.db.execute(
            'SELECT i.*, n.name, n.description, n.danger_tier, n.behavior, '
            '       n.stats, n.loot, n.respawn_delay, n.dialogue, '
            '       n.autoplay_mode, n.autoplay_target '
            'FROM npc_instances i '
            'JOIN npcs n ON i.npc_id = n.npc_id '
            'WHERE i.world=? AND i.next_action_at <= ?',
            (self.world_name, now)
        ).fetchall()
        result = []
        for row in rows:
            r          = dict(row)
            r['stats'] = json.loads(r['stats'] or '{}')
            r['loot']  = json.loads(r['loot']  or '[]')
            result.append(r)
        return result

    def get_autoplayable_instances(self):
        """
        Return combined npc_instances + npcs dicts for all instances that have
        autoplay_mode set, are eligible (tier < 4, not aggressive_talker), and
        are not dead or respawning.  Called by the NPC autoplay director loop.
        """
        rows = self.db.execute(
            'SELECT i.*, n.name, n.description, n.danger_tier, n.behavior, '
            '       n.stats, n.loot, n.respawn_delay, n.dialogue, '
            '       n.autoplay_mode, n.autoplay_target '
            'FROM npc_instances i '
            'JOIN npcs n ON i.npc_id = n.npc_id '
            "WHERE i.world=? AND n.autoplay_mode IS NOT NULL "
            "  AND n.danger_tier < 4 AND n.behavior != 'aggressive_talker' "
            "  AND i.state NOT IN ('dead', 'respawning')",
            (self.world_name,)
        ).fetchall()
        result = []
        for row in rows:
            r             = dict(row)
            r['stats']    = json.loads(r['stats']    or '{}')
            r['loot']     = json.loads(r['loot']     or '[]')
            r['dialogue'] = json.loads(r['dialogue'] or '{}')
            result.append(r)
        return result

    def save_npc_instance(self, instance_id, **fields):
        """UPDATE one or more fields on an npc_instance row."""
        if not fields:
            return
        sets = ', '.join('%s=?' % k for k in fields)
        self.db.execute(
            'UPDATE npc_instances SET %s WHERE instance_id=?' % sets,
            list(fields.values()) + [instance_id]
        )

    # ------------------------------------------------------------------
    # Status effects
    # ------------------------------------------------------------------

    def get_status_effects(self, nick=None, instance_id=None):
        """
        Return status effect dicts for a player nick or NPC instance.
        Provide exactly one of nick or instance_id.
        """
        if nick is not None:
            rows = self.db.execute(
                'SELECT * FROM status_effects WHERE nick=? AND world=?',
                (nick, self.world_name)
            ).fetchall()
        elif instance_id is not None:
            rows = self.db.execute(
                'SELECT * FROM status_effects WHERE instance_id=? AND world=?',
                (instance_id, self.world_name)
            ).fetchall()
        else:
            return []
        return [dict(row) for row in rows]

    def add_status_effect(self, nick, instance_id, effect,
                          severity, ticks_remaining, source):
        """Insert a new status effect row for a player or NPC instance."""
        self.db.execute(
            'INSERT INTO status_effects '
            '  (nick, instance_id, world, effect, severity, ticks_remaining, source) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (nick, instance_id, self.world_name,
             effect, severity, ticks_remaining, source)
        )

    # ------------------------------------------------------------------
    # World bans
    # ------------------------------------------------------------------

    def is_banned(self, nick):
        """Return True if nick is banned from participating in this world."""
        row = self.db.execute(
            'SELECT 1 FROM world_bans WHERE nick=? AND world=?',
            (nick, self.world_name)
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------
    # Tension (in-memory only — see AI Director in design doc)
    # ------------------------------------------------------------------

    def get_tension(self, room_id):
        """Return the current tension float for the room (default 0.0)."""
        return self._tension.get(room_id, 0.0)

    def set_tension(self, room_id, value):
        """Set room tension, clamped to [0.0, 1.0]."""
        self._tension[room_id] = max(0.0, min(1.0, float(value)))

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------

    def commit(self):
        """Flush all pending writes to sqlite."""
        self.db.commit()


# ---------------------------------------------------------------------------
# Direction aliases and guild tables
# ---------------------------------------------------------------------------

# Short-form → full direction name.
_DIR_FULL = {
    'n': 'north', 's': 'south', 'e': 'east',
    'w': 'west',  'u': 'up',    'd': 'down',
}

# Available guilds per base game. Void has none (admins define their own).
_GUILDS = {
    'default':   ['Warrior', 'Mage', 'Rogue', 'Cleric'],
    'cyberpunk': ['Mercenary', 'Ghost', 'Netrunner', 'Ripperdoc'],
    'void':      [],
}


# ---------------------------------------------------------------------------
# Channel/world helpers
# ---------------------------------------------------------------------------

def _world_name_for(channel):
    """
    Derive the world name (e.g. 'default_adventure') from the channel's +MUD
    mode argument.  Returns None if the mode is not set.

    /mode #foo +MUD             → 'default_foo'
    /mode #foo +MUD:cyberpunk   → 'cyberpunk_foo'
    /mode #foo +MUD:void        → 'void_foo'
    """
    arg_list = channel.modes.get('mud')
    if arg_list is None:
        return None
    base = (arg_list[0].lower() if arg_list and arg_list[0] else 'default')
    if base not in _GUILDS:   # unknown base game — fall back to default
        base = 'default'
    return '%s_%s' % (base, channel.name.lstrip('#'))


def _admin_tier(nick, channel):
    """
    Return the MUD admin privilege tier for nick (0–4) based on channel op
    status at the time of the call.

      4  ~  owner  (q)  — full control including destructive ops
      3  &  admin  (a)  — edit world/NPCs/rooms/players; no wipe
      2  @  op     (o)  — teleport, broadcast, edit descriptions
      1  %  halfop (h)  — limited: teleport-to-self, read admin info
      0     player      — no admin access
    """
    m = channel.modes
    if nick in m.get('q', []): return 4
    if nick in m.get('a', []): return 3
    if nick in m.get('o', []): return 2
    if nick in m.get('h', []): return 1
    return 0


def _get_or_init_world(channel, server):
    """
    Return the World for this +MUD channel, creating and caching it on first
    call.  Returns None if the DB is unavailable or +MUD is not set.
    """
    db = getattr(server, 'mud_db', None)
    if db is None:
        return None
    world_name = _world_name_for(channel)
    if world_name is None:
        return None
    world = _worlds.get(world_name)
    if world is None:
        world = World(world_name, db)
        _worlds[world_name] = world
        if hasattr(server, 'mud_worlds'):
            server.mud_worlds[world_name] = world
        if world.model_enabled:
            _ensure_ollama_client(server)
            asyncio.ensure_future(_probe_ollama_tps())
    return world


# ---------------------------------------------------------------------------
# Room display
# ---------------------------------------------------------------------------

def _show_room(client, channel, world, room_id):
    """
    Send the full room description to a single client.

    Output order:
      Room name (bold)
      Description
      Exits: [underlined directions]
      Items: [loot-colored names]     — props + corpse items
      NPCs:  [tier-colored names]
      Players: [bold nicks + level/guild]
    """
    room = world.get_room(room_id)
    if room is None:
        msg(client, channel, 'You are in an undefined room.', C.SYSTEM)
        return

    msg(client, channel, paint(room['name'], bold=True))

    if room.get('description'):
        msg(client, channel, room['description'])

    exits = room.get('exits', {})
    if exits:
        exit_str = '  '.join(paint(d, underline=True) for d in sorted(exits))
        msg(client, channel, paint('Exits:', color=C.SYSTEM) + '  ' + exit_str)
    else:
        msg(client, channel, paint('No exits.', color=C.SYSTEM))

    # Items: props placed in room + items on corpses of dead players here.
    items_here = list(room.get('props', {}).get('items', []))
    rows = world.db.execute(
        'SELECT t.name, i.quantity '
        'FROM inventory i '
        'JOIN items t ON i.item_id = t.item_id AND i.world = t.world '
        'JOIN players p ON i.nick = p.nick AND i.world = p.world '
        'WHERE p.room_id=? AND p.world=? AND p.is_dead=1 AND i.on_corpse=1',
        (room_id, world.world_name)
    ).fetchall()
    for row in rows:
        items_here.append({'name': row['name'], 'qty': row['quantity']})
    if items_here:
        item_str = '  '.join(paint(it['name'], color=C.LOOT) for it in items_here)
        msg(client, channel, paint('Items:', color=C.LOOT) + '  ' + item_str)

    # NPC instances (alive/active only).
    npcs = world.get_npc_instances_in_room(room_id)
    if npcs:
        npc_parts = []
        for npc in npcs:
            tier = min(npc.get('danger_tier', 1), len(C.NPC) - 1)
            npc_parts.append(paint(npc['name'], color=C.NPC[tier], bold=(tier >= 4)))
        msg(client, channel,
            paint('NPCs:', color=C.SYSTEM) + '  ' + '  '.join(npc_parts))

    # Other online players in the same room.
    others = [p for p in world.players_in_room(room_id)
              if p['nick'] != client.nick]
    if others:
        p_parts = []
        for p in others:
            guild_label = (' ' + p['guild']) if p.get('guild') else ''
            p_parts.append(
                paint(p['nick'], bold=True) +
                ' (level %d%s)' % (p['level'], guild_label)
            )
        msg(client, channel,
            paint('Players:', color=C.SYSTEM) + '  ' + '  '.join(p_parts))


# ---------------------------------------------------------------------------
# Splash art — shown on join, keyed by base_game name.
# ---------------------------------------------------------------------------

_SPLASH_ART = {
    'default': r"""
     .   *    .    *    .   *    .   *    .   *   .
  *    .    *   .    *   .    *   .    *   .    *

                          . ' .
                        '       '
                       .    *    .
                        '       '
           /\             ' . '             /\
       /\ /  \/\      /\         /\     /\/  \ /\
      /  X    \/\/\  /  \  /\ /  \  /\/      X  \
     / /  \   /   /\/    \/ X \/  \/  /\   /  \ \
    / /    \_/   /  /\   /     \   \  /  \_/    \ \
___/_/      \___(  /  \_/       \_  \/     )___  \_\__
   |  _   _  |   \/    |  ___  |  \/   |  _   _  |
   | | | | | |   /\    | |   | |   \   | | | | | |
   | | | | | |  /  \   | |[+]| |    \  | | | | | |
   | |_| |_| | /    \  | |___| |     \ | |_| |_| |
   |_________|/______\_|_______|______\|___________|
   |  |||||  |___________________________|  |||||  |
   |__|||||__|___________________________|__|||||__|
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ~   ~   ~   ~   ~   ~   ~   ~   ~   ~   ~   ~   ~
""",
    'cyberpunk': r"""
|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |

    ___  _____     __  ___  ____     ___  ___  ____
   |   ||     |   |  ||   ||    |   |   ||   ||    |
___|   ||     |___|  ||{=}||    |___|   ||{=}||    |__
   |[#]||  _  |   |  ||   ||[#] |   |  ||   ||[#] |
   |   || | | |   |  ||   ||    |   |  ||   ||    |
   |   ||_|=|_|   |  ||___||____|   |  ||___||____|
   |___|   |   |__|  |         |    |  |         |
 __|   |   |   |  |  |         |    |  |    _    |__
|  | # |   |{=}|  |  |    _    |    |  |   |=|   |  |
|__|___|___|___|__|__|___|_|_|__|____|__|___|_|___|__|
=============================================================
|  |   |___|___|  |  |  _|_  |  |__|  |___|___|   |  |
|  |{=}|   |   |  |  | |   | |  |  |  |   |   |{=}|  |
|  |   |[#]|   |  |  | | * | |  |  |  |   |[#]|   |  |
|__|___|___|___|__|__|_|_|_|_|__|__|__|___|___|___|__|
 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
""",
    'void': r"""
         *          .          *          .         *
    .          *          .          *          .

                            *
                           /|\
                          / | \
                         /  |  \
    .                   / . | . \                   .
                       /  . | .  \
         *            / .   *   . \            *
                     /  . .   . .  \
                    /  .  .   .  .  \
                   / .  .  . .  .  . \
    .             /.  .  .  *  .  .  .\             .
                 |.  .  .       .  .  .|
                  |.  .           .  .|
                  |.       . .       .|
                  |.  .           .  .|
                 |.  .  .       .  .  .|
    .             \.  .  .  *  .  .  ./             .
                   \ .  .  . .  .  . /
                    \  .  .   .  .  /
                     \  . .   . .  /
         *            \ .   *   . /            *
                       \  . | .  /
    .                   \ . | . /                   .
                         \  |  /
                          \ | /
                           \|/
                            *


         .          *          .          *          .
""",
}


def _mud_splash(client, channel, world):
    """Send the base-game splash art to a single client, one line per PRIVMSG."""
    art = _SPLASH_ART.get(world.base_game, _SPLASH_ART.get('void', ''))
    for line in art.strip('\n').split('\n'):
        msg(client, channel, line)


# ---------------------------------------------------------------------------
# handle_join / handle_part intercepts
# ---------------------------------------------------------------------------

def _mud_join(client, channel, world):
    """
    Called when a client joins a +MUD channel (via the MUD cmode callable).
    Normal IRC JOIN processing continues after this returns.
    """
    nick = client.nick
    now  = time.time()

    if world.is_banned(nick):
        msg(client, channel, 'You have been banned from this world.', C.SYSTEM)
        return

    _mud_splash(client, channel, world)

    player = world.get_player(nick)

    if player is None:
        # ── New player ──────────────────────────────────────────────────
        world_rec  = world.get_world()
        start_id   = world_rec['start_room_id']
        base       = world.base_game
        # Starting currency: 10 gp in Default/Void; equivalent credits in Cyberpunk.
        start_gold = 150000 if base == 'cyberpunk' else 10

        world.save_player(
            nick,
            room_id=start_id, last_safe_room_id=start_id,
            level=1, xp=0, gold=start_gold,
            max_blood=20, blood=20, max_stamina=10, stamina=10,
            guild=None, last_seen=now, last_regen_at=now,
            colors=1, is_dead=0, respawn_at=None,
            creation_state='guild_select', is_frozen=0,
        )
        world.db.execute(
            'INSERT OR IGNORE INTO autofight_profiles (nick, world) VALUES (?, ?)',
            (nick, world.world_name)
        )
        world.commit()

        client.mud_colors = True
        world._online.add(nick)

        guilds = _GUILDS.get(base, [])
        msg(client, channel,
            paint('Welcome.', bold=True) +
            ' You find yourself at the threshold of %s.' %
            world.world_name.replace('_', ' ').title())
        if guilds:
            msg(client, channel,
                'Choose your guild: ' +
                '  '.join(paint(g, bold=True) for g in guilds))
        else:
            # Void world — no guilds defined, start immediately.
            _wizard_complete(client, channel, world, nick, guild=None)
        return

    # ── Returning player ────────────────────────────────────────────────
    client.mud_colors = bool(player.get('colors', 1))
    world._online.add(nick)

    # If mid-wizard (disconnected during character creation), re-prompt.
    if player.get('creation_state'):
        guilds = _GUILDS.get(world.base_game, [])
        if guilds:
            msg(client, channel,
                'Choose your guild: ' +
                '  '.join(paint(g, bold=True) for g in guilds))
        else:
            _wizard_complete(client, channel, world, nick, guild=None)
        return

    # Offline passive regen, capped at 30 minutes.
    elapsed       = min(now - float(player.get('last_seen') or now), 1800.0)
    regen_blood   = int(elapsed / 120)
    regen_stamina = int(elapsed / max(2, 30 - player['level'] // 5))
    new_blood     = min(player['blood']   + regen_blood,   player['max_blood'])
    new_stamina   = min(player['stamina'] + regen_stamina, player['max_stamina'])

    # Restore to last safe room.
    world_rec = world.get_world()
    room_id   = player.get('last_safe_room_id') or world_rec['start_room_id']

    world.update_player(nick,
                        blood=new_blood, stamina=new_stamina,
                        room_id=room_id, last_seen=now, last_regen_at=now)
    world.commit()

    room     = world.get_room(room_id)
    location = room['name'] if room else 'somewhere'
    healed   = ' Your wounds have healed slightly.' if regen_blood > 0 else ''
    msg(client, channel, 'You wake up in %s.%s' % (location, healed), C.SAFE)
    _show_room(client, channel, world, room_id)


def _mud_part(client, channel, world):
    """
    Called when a client parts a +MUD channel.  Flushes player state and
    cleans up in-memory follow links.  Normal IRC PART continues after this.
    """
    nick = client.nick
    if nick not in world._online:
        return
    world._online.discard(nick)

    player = world.get_player(nick)
    if player:
        world.update_player(nick, last_seen=time.time())
        world.commit()

    # Clear follow links involving this player.
    world._follows.pop(nick, None)
    for follower in list(world._follows):
        if world._follows[follower] == nick:
            world._follows.pop(follower)


# ---------------------------------------------------------------------------
# Character creation wizard
# ---------------------------------------------------------------------------

def _wizard_dispatch(client, channel, world, player, text):
    """Route player input during the character creation flow."""
    state = player.get('creation_state')
    if state == 'guild_select':
        guilds = _GUILDS.get(world.base_game, [])
        chosen = text.strip().title()
        if chosen in guilds:
            _wizard_complete(client, channel, world, client.nick, guild=chosen)
        else:
            msg(client, channel,
                'Choose a guild: ' +
                '  '.join(paint(g, bold=True) for g in guilds),
                C.SYSTEM)


def _wizard_complete(client, channel, world, nick, guild):
    """Finish creation: assign guild, create guild_levels row, place in start room."""
    world_rec = world.get_world()
    start_id  = world_rec['start_room_id']
    world.update_player(nick,
                        guild=guild, creation_state=None,
                        room_id=start_id, last_safe_room_id=start_id)
    if guild:
        world.db.execute(
            'INSERT OR IGNORE INTO guild_levels (nick, world, guild, guild_level) '
            'VALUES (?, ?, ?, 0)',
            (nick, world.world_name, guild)
        )
    world.commit()

    if guild:
        msg(client, channel,
            paint('You have joined the %s guild.' % guild, bold=True) +
            ' Your journey begins.',
            C.LEVELUP)
        _award_guild_spells(world, channel, client, nick, guild, 0, 1)
        world.commit()
    else:
        msg(client, channel, 'Your journey begins.', C.SAFE)

    _show_room(client, channel, world, start_id)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _cmd_look(client, channel, world, player, args):
    target = args.strip().lower()
    if not target:
        _show_room(client, channel, world, player['room_id'])
        return

    room_id = player['room_id']

    # ── look at another player ────────────────────────────────────────────
    others = [p for p in world.players_in_room(room_id) if p['nick'] != client.nick]
    match_p = next((p for p in others if target in p['nick'].lower()), None)
    if match_p:
        nick2  = match_p['nick']
        guild  = match_p.get('guild') or 'no guild'
        level  = match_p['level']
        pct    = match_p['blood'] / max(1, match_p['max_blood'])
        if pct >= 0.90:   health = paint('looks healthy',       color=C.SAFE)
        elif pct >= 0.60: health = paint('looks wounded',       color=C.SYSTEM)
        elif pct >= 0.30: health = paint('looks badly wounded', color=C.DAMAGE_IN)
        else:             health = paint('looks near death',    color=C.DEAD)
        w_dmg, w_name = _equipped_weapon(world, nick2)
        _, a_name     = _equipped_armor(world, nick2)
        msg(client, channel,
            paint(nick2, bold=True) +
            ' — level %d %s — %s' % (level, guild, health))
        if w_name:
            msg(client, channel,
                '  Carrying: ' + paint(w_name, bold=True) +
                (' and ' + paint(a_name, bold=True) if a_name else ''))
        elif a_name:
            msg(client, channel, '  Wearing: ' + paint(a_name, bold=True))
        return

    # ── look at an NPC ────────────────────────────────────────────────────
    npcs = world.get_npc_instances_in_room(room_id)
    match_n = next((n for n in npcs if target in n['name'].lower()), None)
    if match_n:
        tier      = min(match_n.get('danger_tier', 1), len(C.NPC) - 1)
        npc_label = paint(match_n['name'], color=C.NPC[tier], bold=(tier >= 4))
        desc      = match_n.get('description') or 'Nothing remarkable about them.'
        behavior  = match_n.get('behavior', 'idle')
        stats     = match_n.get('stats', {})
        max_b     = stats.get('max_blood', 10)
        cur_b     = match_n.get('current_blood', max_b)
        pct       = cur_b / max(1, max_b)
        if pct >= 0.90:   health = paint('unharmed',      color=C.SAFE)
        elif pct >= 0.60: health = paint('wounded',       color=C.SYSTEM)
        elif pct >= 0.30: health = paint('badly wounded', color=C.DAMAGE_IN)
        else:             health = paint('near death',    color=C.DEAD)
        if behavior == 'passive':
            disposition = paint('seems approachable', color=C.SAFE)
        elif behavior == 'aggressive_talker':
            disposition = paint('seems dangerous but willing to talk', color=C.SYSTEM)
        elif behavior == 'aggressive':
            disposition = paint('looks hostile', color=C.DAMAGE_IN)
        else:
            disposition = paint('ignores you', color=C.SYSTEM)
        msg(client, channel, npc_label)
        msg(client, channel, '  ' + desc)
        msg(client, channel,
            '  %s — %s' % (health, disposition))
        return

    msg(client, channel, "You don't see '%s' here." % args.strip(), C.SYSTEM)


def _cmd_go(client, channel, world, player, args):
    raw_dir   = args.strip().lower()
    direction = _DIR_FULL.get(raw_dir, raw_dir)   # expand 'n' → 'north' etc.

    room = world.get_room(player['room_id'])
    if room is None:
        msg(client, channel, 'You are nowhere.', C.SYSTEM)
        return

    exits   = room.get('exits', {})
    dest_id = exits.get(direction)
    if dest_id is None:
        msg(client, channel,
            "You can't go %s from here." % (direction or 'there'), C.SYSTEM)
        return

    dest_room = world.get_room(dest_id)
    if dest_room is None:
        msg(client, channel, 'That exit leads nowhere.', C.SYSTEM)
        return

    world.update_player(client.nick, room_id=dest_id)
    if dest_room.get('is_safe'):
        world.update_player(client.nick, last_safe_room_id=dest_id)
    _accrue_karma(world, client.nick, 0.001)

    # Move followers with the leader.
    followers = [f for f, l in world._follows.items() if l == client.nick]
    for f_nick in followers:
        world.update_player(f_nick, room_id=dest_id)
        if dest_room.get('is_safe'):
            world.update_player(f_nick, last_safe_room_id=dest_id)
    world.commit()

    _show_room(client, channel, world, dest_id)

    # Deliver destination view to each follower.
    for f_nick in followers:
        follower = next((c for c in channel.clients if c.nick == f_nick), None)
        if follower:
            msg(follower, channel,
                paint(client.nick, bold=True) + ' leads you %s.' % direction)
            _show_room(follower, channel, world, dest_id)


def _guild_change_dialog(client, channel, world, player, npc):
    """
    Handle the __guild_change__ special dialogue trigger.

    If the player types a valid guild name, switch their guild (free, keeps all
    acquired spells).  Otherwise show the list of guilds with a prompt.
    """
    nick   = client.nick
    tier   = min(npc.get('danger_tier', 0), 4)
    label  = paint(npc['name'], color=C.NPC[tier])
    guilds = _GUILDS.get(world.base_game, _GUILDS.get('default', []))

    msg(client, channel,
        label + ' says: ' +
        paint('You may change your guild at any time, for free. '
              'You keep all skills you have already earned.', color=C.NPC[tier]))
    msg(client, channel,
        'Available guilds: ' +
        '  '.join(paint(g, bold=True) for g in guilds), C.SYSTEM)
    msg(client, channel,
        paint('To switch, type: ', color=C.SYSTEM) +
        paint('guild <name>', bold=True), C.SYSTEM)


def _guild_change_dialog_confirm(client, channel, world, player, guild_name):
    """
    Complete a guild change for a player who has typed 'guild <name>'.
    Called from the main command dispatch when the player is not in creation state.
    With no args, shows available guilds.
    """
    nick   = client.nick
    guilds = _GUILDS.get(world.base_game, _GUILDS.get('default', []))

    if not guild_name:
        if not guilds:
            msg(client, channel,
                'No guilds are defined in this world.', C.SYSTEM)
            return
        msg(client, channel,
            'Available guilds: ' +
            '  '.join(paint(g, bold=True) for g in guilds), C.SYSTEM)
        msg(client, channel,
            paint('Type: guild <name>', bold=True) + '  to change guild.', C.SYSTEM)
        return

    guild_match = next((g for g in guilds if guild_name.lower() in g.lower()), None)
    if guild_match is None:
        msg(client, channel,
            "No guild named '%s'. Available: %s" % (
                guild_name, ', '.join(guilds)), C.SYSTEM)
        return

    old_guild = player.get('guild')
    if old_guild and old_guild.lower() == guild_match.lower():
        msg(client, channel,
            'You are already in the %s guild.' % guild_match, C.SYSTEM)
        return

    # Ensure guild_levels row exists for the new guild (start at 0 if new).
    world.db.execute(
        'INSERT OR IGNORE INTO guild_levels (nick, world, guild, guild_level) '
        'VALUES (?, ?, ?, 0)',
        (nick, world.world_name, guild_match)
    )
    world.update_player(nick, guild=guild_match)
    world.commit()
    msg(client, channel,
        paint('You have joined the %s guild.' % guild_match, bold=True) +
        '  Your previous skills are retained.', C.LEVELUP)


def _cmd_talk(client, channel, world, player, args):
    """
    talk <npc>                  — NPC delivers their greeting
    talk <npc> about <topic>    — NPC responds to a topic
    buy <item>                  — purchase item from a vendor NPC (via vendor topic)
    sell <item>                 — sell an item to a vendor NPC
    """
    nick     = client.nick
    room_id  = player['room_id']
    currency = 'credits' if world.base_game == 'cyberpunk' else 'gold'

    if not args:
        msg(client, channel, 'Talk to whom?  talk <npc> [about <topic>]', C.SYSTEM)
        return

    # Parse: talk <npc> [about <topic>] or talk <npc> buy <item> / sell <item>
    parts = args.split(None, 2)
    npc_name_arg = parts[0].lower()

    topic = None
    subcommand = None  # 'buy' or 'sell'
    sub_arg    = None
    if len(parts) >= 2:
        if parts[1].lower() == 'about' and len(parts) >= 3:
            topic = parts[2].lower()
        elif parts[1].lower() in ('buy', 'sell'):
            subcommand = parts[1].lower()
            sub_arg    = parts[2].lower() if len(parts) >= 3 else None
        else:
            # treat rest as topic directly
            topic = ' '.join(parts[1:]).lower()

    npcs = world.get_npc_instances_in_room(room_id)
    npc  = next((n for n in npcs
                 if npc_name_arg in n['name'].lower()), None)
    if npc is None:
        msg(client, channel, 'There is no "%s" here.' % parts[0], C.SYSTEM)
        return

    tier      = min(npc.get('danger_tier', 1), len(C.NPC) - 1)
    npc_label = paint(npc['name'], color=C.NPC[tier])
    dialogue  = npc.get('dialogue') or {}

    # ── Vendor sub-commands ────────────────────────────────────────────────
    if subcommand == 'buy':
        # Show vendor listing if no item specified
        items = world.db.execute(
            'SELECT * FROM items WHERE world=? ORDER BY value',
            (world.world_name,)
        ).fetchall()
        vendor_items = [dict(r) for r in items]
        if not sub_arg:
            if not vendor_items:
                msg(client, channel,
                    npc_label + ' has nothing for sale.', C.SYSTEM)
                return
            msg(client, channel,
                npc_label + ' says: ' +
                paint(dialogue.get('greeting', 'What do you want?'), color=C.NPC[tier]))
            for it in vendor_items:
                stats = json.loads(it['stats']) if isinstance(it['stats'], str) else it['stats']
                stat_str = ''
                if stats:
                    stat_str = ' (' + ', '.join('%s %+d' % (k, v)
                                                for k, v in stats.items()) + ')'
                msg(client, channel,
                    '  ' + paint(it['name'], bold=True) +
                    '%s — %s' % (stat_str,
                                 paint('%d %s' % (it['value'], currency),
                                       color=C.CURRENCY)))
            return
        # Buy a specific item
        match = next((i for i in vendor_items
                      if sub_arg in i['name'].lower()), None)
        if match is None:
            msg(client, channel,
                npc_label + " doesn't carry that.", C.SYSTEM)
            return
        cost = match['value']
        if player['gold'] < cost:
            msg(client, channel,
                paint('You need %d %s.' % (cost, currency), color=C.SYSTEM))
            return
        world.update_player(nick, gold=player['gold'] - cost)
        existing = world.db.execute(
            'SELECT rowid FROM inventory WHERE nick=? AND world=? AND item_id=? AND on_corpse=0',
            (nick, world.world_name, match['item_id'])
        ).fetchone()
        if existing:
            world.db.execute(
                'UPDATE inventory SET quantity = quantity + 1 '
                'WHERE rowid=?', (existing[0],)
            )
        else:
            world.db.execute(
                'INSERT INTO inventory (nick, world, item_id, quantity, equipped, on_corpse) '
                'VALUES (?, ?, ?, 1, 0, 0)',
                (nick, world.world_name, match['item_id'])
            )
        world.commit()
        msg(client, channel,
            npc_label + ' hands you ' + paint(match['name'], bold=True) +
            '.  ' + paint('-%d %s' % (cost, currency), color=C.SYSTEM))
        return

    if subcommand == 'sell':
        if not sub_arg:
            msg(client, channel,
                'sell what?  talk %s sell <item>' % parts[0], C.SYSTEM)
            return
        row = world.db.execute(
            'SELECT i.*, t.name, t.value FROM inventory i '
            'JOIN items t ON i.item_id = t.item_id AND i.world = t.world '
            'WHERE i.nick=? AND i.world=? AND i.on_corpse=0 '
            'AND lower(t.name) LIKE ?',
            (nick, world.world_name, '%' + sub_arg + '%')
        ).fetchone()
        if row is None:
            msg(client, channel, "You don't have that.", C.SYSTEM)
            return
        sell_price = max(1, row['value'] // 2)
        # Remove one from inventory
        if row['quantity'] > 1:
            world.db.execute(
                'UPDATE inventory SET quantity = quantity - 1 '
                'WHERE nick=? AND world=? AND item_id=?',
                (nick, world.world_name, row['item_id'])
            )
        else:
            world.db.execute(
                'DELETE FROM inventory WHERE nick=? AND world=? AND item_id=?',
                (nick, world.world_name, row['item_id'])
            )
        world.update_player(nick, gold=player['gold'] + sell_price)
        world.commit()
        msg(client, channel,
            npc_label + ' takes ' + paint(row['name'], bold=True) +
            ' and hands you ' +
            paint('+%d %s' % (sell_price, currency), color=C.CURRENCY) + '.')
        return

    # ── Dialogue ───────────────────────────────────────────────────────────
    if topic is None:
        # Just greeting
        greeting = dialogue.get('greeting')
        if greeting:
            msg(client, channel,
                npc_label + ' says: ' + paint(greeting, color=C.NPC[tier]))
        else:
            msg(client, channel,
                npc_label + ' stares blankly at you.', C.SYSTEM)
        topics = dialogue.get('topics', {})
        if topics:
            msg(client, channel,
                paint('Topics:', color=C.SYSTEM) + '  ' +
                '  '.join(paint(t, bold=True) for t in topics))
        return

    topics = dialogue.get('topics', {})
    # Substring match
    matched_key = next((k for k in topics if topic in k.lower()), None)
    if matched_key is None:
        default = dialogue.get('default')
        # Passive/idle NPCs with dialogue are routed through ollama when the
        # model is on — scripted default is kept as the model-off fallback.
        _is_talkable = npc.get('behavior') in ('passive', 'idle') and bool(dialogue)
        if world.model_enabled and _ollama_client is not None and _is_talkable:
            room   = world.get_room(room_id)
            speech = topic or (args.split('about', 1)[-1].strip() if 'about' in args else args)
            asyncio.ensure_future(
                _ollama_npc_response(client, channel, world, player, npc, room, speech))
        elif default:
            msg(client, channel,
                npc_label + ' says: ' + paint(default, color=C.NPC[tier]))
        else:
            msg(client, channel,
                npc_label + ' shrugs.', C.SYSTEM)
        return

    response = topics[matched_key]
    if response == '__vendor__':
        _cmd_talk(client, channel, world, player, parts[0] + ' buy')
        return

    if response == '__guild_change__':
        _guild_change_dialog(client, channel, world, player, npc)
        return

    if isinstance(response, str) and response.startswith('__mission__:'):
        quest_id = response.split(':', 1)[1]
        quest = world.db.execute(
            'SELECT * FROM quests WHERE quest_id=? AND world=?',
            (quest_id, world.world_name)
        ).fetchone()
        if quest is None:
            msg(client, channel,
                npc_label + ' has nothing to offer right now.', C.SYSTEM)
            return
        existing = world.db.execute(
            'SELECT * FROM player_quests WHERE nick=? AND world=? AND quest_id=?',
            (nick, world.world_name, quest_id)
        ).fetchone()
        currency = 'credits' if world.base_game == 'cyberpunk' else 'gold'
        obj = json.loads(quest['objective'])
        if existing:
            if existing['status'] == 'complete':
                msg(client, channel,
                    npc_label + ' says: ' +
                    paint('You have already completed this task. Well done.', color=C.NPC[tier]))
            else:
                needed = obj.get('count', 1)
                msg(client, channel,
                    npc_label + ' says: ' +
                    paint('How goes it? %d of %d done so far.' % (existing['progress'], needed),
                          color=C.NPC[tier]))
        else:
            world.db.execute(
                'INSERT INTO player_quests (nick, world, quest_id, status, progress) '
                'VALUES (?, ?, ?, ?, ?)',
                (nick, world.world_name, quest_id, 'active', 0)
            )
            world.commit()
            reward_parts = []
            if quest['reward_xp']:
                reward_parts.append('%d XP' % quest['reward_xp'])
            if quest['reward_gold']:
                reward_parts.append('%d %s' % (quest['reward_gold'], currency))
            if quest['reward_item']:
                reward_parts.append(quest['reward_item'])
            reward_str = ('  ' + paint('Reward: ' + ', '.join(reward_parts), color=C.CURRENCY)
                          if reward_parts else '')
            msg(client, channel,
                paint('Mission accepted: ', bold=True) +
                paint(quest['title'], bold=True) + reward_str)
            msg(client, channel, '  ' + (quest['description'] or ''), C.SYSTEM)
            if obj.get('type') == 'kill':
                msg(client, channel,
                    '  Objective: kill %d × %s' % (obj['count'], obj['npc_name']), C.SYSTEM)
        return

    msg(client, channel,
        npc_label + ' says: ' + paint(response, color=C.NPC[tier]))


def _cmd_say(client, channel, world, player, args):
    if not args:
        return
    room_id = player['room_id']
    line    = paint(client.nick, bold=True) + ' says: ' + args
    for target in list(channel.clients):
        t_player = world.get_player(target.nick)
        if t_player and t_player.get('room_id') == room_id:
            msg(target, channel, line)
    _accrue_karma(world, client.nick, 0.001)
    world.commit()


def _cmd_emote(client, channel, world, player, args):
    if not args:
        return
    room_id = player['room_id']
    line    = paint(client.nick, bold=True) + ' ' + args
    for target in list(channel.clients):
        t_player = world.get_player(target.nick)
        if t_player and t_player.get('room_id') == room_id:
            msg(target, channel, line)


def _cmd_who(client, channel, world, player, args):
    online = world.online_players()
    if not online:
        msg(client, channel, 'No one else is online.', C.SYSTEM)
        return
    for p in online:
        guild_label = (' ' + p['guild']) if p.get('guild') else ''
        msg(client, channel,
            paint(p['nick'], bold=True) +
            ' — level %d%s' % (p['level'], guild_label))


def _cmd_colors(client, channel, world, player, args):
    setting = args.strip().lower()
    if setting == 'on':
        client.mud_colors = True
        world.update_player(client.nick, colors=1)
        world.commit()
        msg(client, channel, 'Colors enabled.', C.SYSTEM)
    elif setting == 'off':
        client.mud_colors = False
        world.update_player(client.nick, colors=0)
        world.commit()
        msg(client, channel, 'Colors disabled.')
    else:
        current = 'on' if getattr(client, 'mud_colors', True) else 'off'
        msg(client, channel,
            'Color display is %s.  Usage: colors on / colors off' % current,
            C.SYSTEM)


def _cmd_follow(client, channel, world, player, args):
    target_nick = args.strip()
    if not target_nick:
        msg(client, channel, 'Usage: follow <nick>', C.SYSTEM)
        return
    if target_nick == client.nick:
        msg(client, channel, "You can't follow yourself.", C.SYSTEM)
        return
    # Prevent follow loops.
    if world._follows.get(target_nick) == client.nick:
        msg(client, channel,
            paint(target_nick, bold=True) + ' is already following you.',
            C.SYSTEM)
        return
    if target_nick not in world._online:
        msg(client, channel,
            paint(target_nick, bold=True) + ' is not online.', C.SYSTEM)
        return
    world._follows[client.nick] = target_nick
    msg(client, channel,
        'You begin following ' + paint(target_nick, bold=True) + '.')
    leader = next((c for c in channel.clients if c.nick == target_nick), None)
    if leader:
        msg(leader, channel,
            paint(client.nick, bold=True) + ' begins following you.')


def _cmd_unfollow(client, channel, world, player, args):
    if client.nick not in world._follows:
        msg(client, channel, "You aren't following anyone.", C.SYSTEM)
        return
    leader_nick = world._follows.pop(client.nick)
    msg(client, channel,
        'You stop following ' + paint(leader_nick, bold=True) + '.')


def _cmd_party(client, channel, world, player, args):
    followers = [f for f, l in world._follows.items() if l == client.nick]
    leader    = world._follows.get(client.nick)

    members = []
    if leader:
        lp = world.get_player(leader)
        if lp:
            members.append((leader, lp))
    members.append((client.nick, player))
    for f_nick in followers:
        fp = world.get_player(f_nick)
        if fp:
            members.append((f_nick, fp))

    if len(members) < 2:
        msg(client, channel, "You're not in a party.", C.SYSTEM)
        return
    for nick, p in members:
        bp = int(100 * p['blood']   / max(1, p['max_blood']))
        sp = int(100 * p['stamina'] / max(1, p['max_stamina']))
        msg(client, channel,
            paint(nick, bold=True) +
            '  blood: %d%%  stamina: %d%%' % (bp, sp))


_HELP_TOPICS = {}   # populated after function definitions; see _build_help_topics()


def _cmd_help(client, channel, world, player, args):
    if player.get('creation_state'):
        msg(client, channel, 'Type a guild name to begin your journey.', C.SYSTEM)
        return
    if player.get('is_dead'):
        msg(client, channel, 'You are dead. Wait for respawn.', C.DEAD)
        return

    tier  = _admin_tier(client.nick, channel)
    topic = args.strip().lower()
    if topic:
        _admin_topics = {'admin', '@', '@commands', 'commands'}
        is_admin_topic = topic in _admin_topics or topic.startswith('@')
        if is_admin_topic and tier < 1:
            msg(client, channel,
                'Admin help requires at least halfop (+h).', C.SYSTEM)
            return
        lines = _HELP_TOPICS.get(topic)
        if lines is None:
            # fuzzy match — exclude admin topics for non-admins
            matches = [k for k in _HELP_TOPICS
                       if topic in k
                       and (tier >= 1 or not (k in _admin_topics or k.startswith('@')))]
            if len(matches) == 1:
                lines = _HELP_TOPICS[matches[0]]
            elif matches:
                msg(client, channel,
                    'Did you mean: ' + '  '.join(paint(m, bold=True) for m in sorted(matches)),
                    C.SYSTEM)
                return
            else:
                msg(client, channel,
                    "No help for '%s'. Type %s for the full list." % (
                        args.strip(), paint('help', bold=True)), C.SYSTEM)
                return
        for line in lines:
            msg(client, channel, line, C.SYSTEM)
        return

    lines = [
        paint('Movement:', bold=True) +
        '  go <dir>   n s e w u d   north south east west up down',
        paint('Look:', bold=True)   + '  look (l)   look <name>   examine <name>',
        paint('Talk:', bold=True)   + '  say <text>   emote <text>   me <text>',
        paint('Info:', bold=True)   + '  who   party   stats (score)   colors on/off',
        paint('Items:', bold=True)  + '  inventory (inv i)   equip <item>   unequip   spells',
        paint('Combat:', bold=True) +
        '  attack (a) <target>   flee   defend (d)   use <item|spell>',
        paint('Autoheal:', bold=True) +
        '  autoheal <pct>   autoheal <pct> <item>   autoheal off',
        paint('Autoloot:', bold=True) +
        '  autoloot on|off   (level-weighted lottery; NPCs always compete)',
        paint('Autofight:', bold=True) +
        '  af show   af spell <name>   af spell none   af style <tier>:<weight>',
        paint('Autoplay:', bold=True) +
        '  autoplay <mode>   autoplay off   autoplay respawn on|off',
        '           modes: passive  defender  skirmisher  explorer  hunter  grinder',
        paint('Follow:', bold=True) + '  follow <nick>   unfollow',
        paint('NPCs:', bold=True) +
        '  talk <npc> [about <topic>]   ask <npc> about <topic>',
        paint('Trade:', bold=True) +
        '  talk <npc> buy [item]   talk <npc> sell <item>   buy/sell shorthand',
        paint('Quests:', bold=True) +
        '  talk <npc> about quest   stats (shows active missions)',
        paint('Guild:', bold=True) +
        '  guild — show available guilds   guild <name> — switch guild',
        paint('Help:', bold=True) +
        '  help <topic>   topics: go look say emote who party stats colors '
        'inventory equip unequip spells attack flee defend use '
        'autofight autoheal autoloot autoplay '
        'follow unfollow talk buy sell quests guild',
    ]
    if tier >= 1:
        lines += [
            '',
            paint('Admin:', bold=True) +
            '  @list <rooms|npcs|items|bans|players|themes|quests>',
            '         @create <room|npc|theme>  @attach <room_id> <dir>  @modify <room|npc|player|world>',
            '         @announce  @goto  @kick  @ban  @unban  @freeze  @unfreeze',
            '         @spawn  @generate  @theme  @reset world',
            "  Type %s for the full admin reference and tier requirements." % (
                paint('help admin', bold=True),),
        ]
    for line in lines:
        msg(client, channel, line, C.SYSTEM)


def _build_help_topics():
    """Populate _HELP_TOPICS with per-command help text."""
    T = _HELP_TOPICS
    H = paint  # shorthand

    T['go'] = T['move'] = T['movement'] = [
        H('go <direction>', bold=True) + ' — move to an adjacent room.',
        '  Directions: north (n)  south (s)  east (e)  west (w)  up (u)  down (d)',
        '  Example: go north   or just: n',
    ]
    T['look'] = T['l'] = T['examine'] = T['ex'] = [
        H('look', bold=True) + ' — describe the current room.',
        H('look <name>', bold=True) + ' — examine a player or NPC in the room.',
        '  Shows health status, equipped gear (players) or description and disposition (NPCs).',
        '  Aliases: l   examine   ex',
    ]
    T['say'] = [
        H('say <text>', bold=True) + ' — speak aloud to everyone in the room.',
        '  Only players in the same room hear you.',
    ]
    T['emote'] = T['me'] = [
        H('emote <text>', bold=True) + ' — perform an emote visible to the room.',
        '  Example: emote waves.  →  YourNick waves.',
        '  Alias: me',
    ]
    T['who'] = [
        H('who', bold=True) + ' — list all players currently online in this world.',
        '  Shows nick, level, and guild.',
        H('who all', bold=True) + ' — list every player ever created, with last-seen time.',
    ]
    T['party'] = [
        H('party', bold=True) + ' — show blood% and stamina% for all players in your room.',
    ]
    T['stats'] = T['score'] = [
        H('stats', bold=True) + ' — show your character sheet.',
        '  Displays level, guild rank, blood, stamina, gold/credits, XP, equipped weapon,',
        '  active buffs, and any active missions.',
        '  Alias: score',
    ]
    T['colors'] = T['colour'] = T['colours'] = [
        H('colors on', bold=True) + ' — enable colour output (default).',
        H('colors off', bold=True) + ' — disable colour output (plain text).',
    ]
    T['inventory'] = T['inv'] = T['i'] = [
        H('inventory', bold=True) + ' — list everything you are carrying.',
        '  Shows item name, type, quantity, and whether it is equipped.',
        '  Aliases: inv   i',
    ]
    T['equip'] = [
        H('equip <item>', bold=True) + ' — equip a weapon or armour from your inventory.',
        '  Only one weapon and one armour piece can be equipped at a time.',
        '  Equipping a new item of the same type automatically unequips the old one.',
    ]
    T['unequip'] = [
        H('unequip', bold=True) + ' — remove all equipped items (stow weapon and armour).',
    ]
    T['spells'] = T['hacks'] = T['abilities'] = [
        H('spells', bold=True) + ' — list all spells you know and their stamina costs.',
        '  Spells are awarded automatically as you level up within your guild.',
        '  Use them in combat with: use <spell name>',
        '  Aliases: hacks   abilities',
    ]
    T['attack'] = T['a'] = T['combat'] = [
        H('attack <target>', bold=True) + ' — strike an NPC in your current room.',
        '  You can use a partial name: attack gob   will target any goblin.',
        '  The NPC will fight back after your strike.',
        '  Alias: a',
    ]
    T['flee'] = [
        H('flee', bold=True) + ' — attempt to escape from combat.',
        '  Success is not guaranteed and costs stamina.',
        '  You will be moved to a random adjacent room on success.',
    ]
    T['defend'] = T['d'] = [
        H('defend', bold=True) + ' — take a defensive stance for one round.',
        '  Reduces incoming damage on the next NPC attack this round.',
        '  Alias: d',
    ]
    T['use'] = [
        H('use <item or spell>', bold=True) + ' — use a consumable item or cast a spell.',
        '  Consumables: use health potion   use antidote   use stamina draught',
        '  Spells: use fireball   use heal   use magic missile',
        '  Spells cost stamina. Type %s to see what you know.' % H('spells', bold=True),
    ]
    T['autoheal'] = [
        H('autoheal', bold=True) + ' — auto-use a healing item when blood drops low.',
        '  Fires whenever an NPC is attacking you and your blood is below the threshold.',
        '  Tagged [AF] in output.',
        '',
        H('autoheal <pct>', bold=True) + '           — heal below this % blood.',
        H('autoheal <pct> <item>', bold=True) + '    — prefer items matching a name fragment.',
        H('autoheal off', bold=True) + '             — disable.',
        H('autoheal', bold=True) + '                — show current setting.',
        '  Examples:',
        '    autoheal 30              (any consumable, at 30% blood)',
        '    autoheal 40 potion       (prefer items whose name contains "potion")',
    ]
    T['autoloot'] = [
        H('autoloot', bold=True) + ' — opt into the corpse-loot lottery.',
        '',
        H('autoloot on', bold=True) + '   — enter the lottery when a corpse appears in your room.',
        H('autoloot off', bold=True) + '  — opt out.',
        H('autoloot', bold=True) + '      — show current setting.',
        '  How it works:',
        '    All eligible actors in the room compete — players with autoloot on plus',
        '    any non-passive NPCs (they always enter).  Each actor\'s odds are',
        '    proportional to their level.  The winner takes everything on the corpse.',
        '    If no eligible actors are present the loot falls back to direct',
        '    distribution among the players who dealt damage.',
        '  Tagged [AL] in output.',
    ]
    T['autofight'] = T['af'] = [
        H('autofight', bold=True) + ' (af) — configure reactive combat spell and style.',
        '  Autofight fires automatically when an NPC is attacking you.',
        '  For healing use ' + H('autoheal', bold=True) +
        ', for looting use ' + H('autoloot', bold=True) +
        ', for autonomous play use ' + H('autoplay', bold=True) + '.',
        '',
        H('autofight show', bold=True) + ' — display spell and style settings.',
        H('autofight spell <name>', bold=True) + ' — cast this spell every autofight turn.',
        '    Example: autofight spell fireball',
        '    Multi-word: autofight spell magic missile',
        H('autofight spell none', bold=True) + ' — revert to melee attacks.',
        H('autofight style <tier>:<weight> ...', bold=True) + ' — set attack style weights.',
        '    Tiers: cautious  standard  heavy  reckless',
        '    Example: autofight style heavy:50 reckless:20',
        '  Alias: af',
    ]
    T['autoplay'] = [
        H('autoplay', bold=True) + ' — run your character autonomously.',
        '  Acts every ~8 seconds on the director tick.  Tagged [AP] in look output.',
        '',
        H('autoplay <mode>', bold=True) + ' — set a mode (see below).',
        H('autoplay off', bold=True) + '    — stop.',
        H('autoplay respawn on|off', bold=True) + ' — resume after death (default: on).',
        H('autoplay', bold=True) + '        — show current mode.',
        '',
        '  Modes:',
        '    ' + H('passive', bold=True) +
        '    — react only; autofight handles combat, nothing proactive.',
        '    ' + H('defender', bold=True) +
        '   — attack hostile NPCs already in the room; does not move.',
        '    ' + H('skirmisher', bold=True) +
        ' — move through exits (prefers unvisited rooms); fights back if attacked.',
        '    ' + H('explorer', bold=True) +
        '   — move using a weighted exit lottery (deweights backtracking);',
        '                flees combat rather than engaging.',
        '    ' + H('hunter', bold=True) +
        '    — seeks and attacks any NPC; patrols rooms to find them.',
        '    ' + H('grinder <target>', bold=True) +
        ' — like hunter but only attacks NPCs whose name matches target.',
        '                Example: autoplay grinder goblin',
    ]
    T['follow'] = [
        H('follow <nick>', bold=True) + ' — follow another player through exits.',
        '  You will automatically move when they move.',
        '  You cannot follow someone who is already following you.',
    ]
    T['unfollow'] = [
        H('unfollow', bold=True) + ' — stop following.',
    ]
    T['talk'] = T['ask'] = [
        H('talk <npc>', bold=True) + ' — greet an NPC and see their available topics.',
        H('talk <npc> about <topic>', bold=True) + ' — ask about a specific topic.',
        H('ask <npc> about <topic>', bold=True) + ' — same as talk ... about.',
        '  Topic matching is case-insensitive and partial.',
        '  Example: talk crier about dungeon',
        '  Special topics: buy  sell  quest',
    ]
    T['buy'] = [
        H('talk <npc> buy', bold=True) + ' — list items a vendor NPC sells.',
        H('talk <npc> buy <item>', bold=True) + ' — purchase an item.',
        H('buy <npc> <item>', bold=True) + ' — shorthand.',
        '  Example: buy innkeeper health potion',
    ]
    T['sell'] = [
        H('talk <npc> sell <item>', bold=True) + ' — sell an item from your inventory.',
        H('sell <npc> <item>', bold=True) + ' — shorthand.',
        '  You receive 50% of the item\'s base value.',
    ]
    T['quests'] = T['quest'] = T['missions'] = [
        H('Quests / Missions', bold=True),
        '  Find quests by talking to NPCs: %s' % H('talk <npc> about quest', bold=True),
        '  Once accepted, kill progress updates automatically as you fight.',
        '  Check active missions: %s' % H('stats', bold=True),
        '  Return to the quest-giver to confirm completion and collect rewards.',
    ]
    T['admin'] = T['@'] = T['@commands'] = T['commands'] = [
        H('Admin commands', bold=True) + ' — prefix any command with @.',
        '  Requires at least halfop (+h) in the channel.',
        '  Tier requirements: % halfop  @ op  & admin  ~ owner',
        '',
        '  % halfop:  @who  @rooms  @list rooms|npcs|items|bans|players|themes|quests',
        '             @generate preview',
        '  @    op:   @announce  @goto  @kick  @freeze  @unfreeze',
        '             @create room <dir> [name]  @attach <room_id> <dir>',
        '             @room <name|desc|exit|safe>',
        '             @spawn npc/prop  @generate area/room',
        '  &  admin:  @npc <list|show|add|set...>  @create npc <name>  @create theme <name>',
        '             @player <nick> <field> <value>  @world <subcommand>',
        '             @ban  @unban  @spawn copy  @theme (write)',
        '  ~  owner:  @reset world  @difficulty  @world model on|off',
        '',
        H('@who', bold=True)      + '        — admin player list with room, blood%, frozen status.',
        H('@rooms', bold=True)    + '      — list all rooms with ID and safe status.',
        H('@list', bold=True)     + '       — list rooms/npcs/items/bans/players/themes/quests.',
        H('@generate', bold=True) + '   — procedurally generate rooms from a theme.',
        H('@announce', bold=True) + '   — broadcast a message to all online players.',
        H('@goto', bold=True)     + '       — teleport to a room or player.',
        H('@kick', bold=True)     + '       — eject a player from the world.',
        H('@freeze', bold=True)   + '     — immobilise a player (blocks all commands).',
        H('@unfreeze', bold=True) + '   — release a frozen player.',
        H('@create', bold=True)   + '     — create a room, NPC template, or theme.',
        H('@attach', bold=True)   + '     — wire a bidirectional exit between two rooms.',
        H('@room', bold=True)     + '       — rename, redescribe, add exits, or mark safe.',
        H('@spawn', bold=True)    + '      — place NPC or item instances; copy cross-world.',
        H('@npc', bold=True)      + '        — edit NPC templates (dialogue, behavior, autoplay).',
        H('@modify', bold=True)   + '     — thin wrapper: modify room/npc/player/world.',
        H('@ban', bold=True)      + '        — ban a player from this world.',
        H('@unban', bold=True)    + '      — remove a ban.',
        H('@player', bold=True)   + '     — edit a player record (blood, gold, level, etc.).',
        H('@world', bold=True)    + '      — world settings overview and editor.',
        H('@theme', bold=True)    + '      — manage procedural generation themes.',
        H('@difficulty', bold=True) + '  — tune the XP curve (kills-to-cap).',
        H('@reset', bold=True)    + '      — wipe and re-seed the entire world.',
        '',
        '  Type %s for detailed help on any command.' % H('help @<cmd>', bold=True),
    ]
    T['@npc'] = T['npc'] = [
        H('@npc', bold=True) + ' — edit NPC templates.  Requires admin (&).',
        '',
        H('@npc list', bold=True) + '  — list all NPC templates.',
        H('@npc show <name>', bold=True) + '  — dump full record: stats, loot, tier, behavior, autoplay, dialogue.',
        H('@npc add <name>', bold=True) + '  — create a new NPC here (default stats).',
        H('@npc setgreeting <name> <text>', bold=True),
        H('@npc addtopic <name> <key> <text>', bold=True),
        '  Special values: __vendor__  __mission__:<quest_id>',
        H('@npc deltopic <name> <key>', bold=True),
        H('@npc setdefault <name> <text>', bold=True),
        H('@npc setbehavior <name> <behavior>', bold=True),
        '  Behaviors: passive  aggressive  aggressive_talker  patrol  idle',
        H('@npc setautoplay <name> <mode|off>', bold=True),
        '  Modes: passive  defender  skirmisher  explorer  hunter  grinder  off',
        '  grinder accepts an optional target filter: @npc setautoplay <name> grinder <filter>',
        '  Not available for tier 4+ NPCs or aggressive_talker behavior.',
    ]
    T['@announce'] = [
        H('@announce <text>', bold=True) + ' — broadcast to all online players.  op (@).',
    ]
    T['@goto'] = [
        H('@goto <room_name|nick>', bold=True) + ' — teleport to a room or player.  op (@).',
        '  Partial name matching.  Tries players first, then rooms.',
        '  Example: @goto throne room',
        '  Example: @goto luke',
    ]
    T['@rooms'] = [
        H('@rooms', bold=True) + ' — list all rooms in this world.  halfop (%).',
        '  Shows room_id, name, and safe status.',
    ]
    T['@room'] = [
        H('@room', bold=True) + ' — edit the current room.  op (@).',
        '',
        H('@room name <text>', bold=True) + '  — rename this room.',
        H('@room desc <text>', bold=True) + '  — set room description.',
        H('@room exit <dir> <room>', bold=True) + '  — add an exit.',
        '  direction: north south east west up down  (abbreviations ok)',
        '  room: partial name or room_id',
        '  Example: @room exit north dungeon entrance',
        H('@room safe on|off', bold=True) + '  — mark as safe (no combat respawn here).',
    ]
    T['@who'] = [
        H('@who', bold=True) + ' — admin who list.  halfop (%).',
        '  Shows nick, level, guild, exact room, blood%, stamina%, frozen status.',
        H('@who all', bold=True) + '  — all players ever created, with last-seen time.',
    ]
    T['@kick'] = [
        H('@kick <nick> [reason]', bold=True) + ' — eject a player from the world.  op (@).',
        '  The player stays in the IRC channel but loses their online status.',
        '  They can re-enter by speaking in the channel.',
    ]
    T['@ban'] = T['@unban'] = [
        H('@ban <nick> [reason]', bold=True) + ' — ban a player.  admin (&).',
        H('@ban list', bold=True) + '  — list all bans.  halfop (%).',
        H('@unban <nick>', bold=True) + '  — remove a ban.  admin (&).',
    ]
    T['@freeze'] = T['@unfreeze'] = [
        H('@freeze <nick>', bold=True) + ' — immobilise a player.  op (@).',
        '  Frozen players cannot move or issue commands (except look).',
        H('@unfreeze <nick>', bold=True) + '  — release a frozen player.  op (@).',
    ]
    T['@player'] = [
        H('@player <nick> <field> <value>', bold=True) + ' — edit a player record.  admin (&).',
        '  Fields: blood  max_blood  stamina  max_stamina  gold  level  xp',
        '          guild  room_id  is_frozen  is_dead',
        '  Example: @player luke gold 500',
        '  Example: @player luke room_id 1',
    ]
    T['@world'] = [
        H('@world', bold=True) + ' — world settings overview and editor.  admin (&).',
        '',
        H('@world', bold=True) + '  — show live settings overview (counts, xp_factor, model).',
        '',
        H('@world description <text>', bold=True) + '  — set world description.',
        H('@world magic_name <name>', bold=True) + '  — name of the magic/tech system.',
        H('@world magic_source levelup|item|vendor', bold=True) + '  — how spells are acquired.',
        H('@world model on|off', bold=True) + '  — toggle NPC AI (requires MUD_MODEL set).',
    ]
    T['@reset'] = [
        H('@reset world', bold=True) + ' — wipe and re-seed the entire world.  owner (~).',
        '  Destroys all rooms, NPCs, player records, themes, and quests.',
        '  All online players are re-joined into the freshly seeded world.',
        '  This cannot be undone.',
    ]
    T['@spawn'] = [
        H('@spawn', bold=True) + ' — manage NPC and item instances.',
        '',
        H('@spawn list npcs [query] [--all]', bold=True) + '  halfop (%).',
        H('@spawn list props [query] [--all]', bold=True) + '  halfop (%).',
        '  Lists templates. --all searches every world on this server.',
        '  Results are numbered; use the number with @spawn copy.',
        '',
        H('@spawn npc <name|id>', bold=True) + '  — spawn NPC instance here.  op (@).',
        H('@spawn prop <name|id>', bold=True) + '  — place item in this room.  op (@).',
        '',
        H('@spawn copy npc <world:id|n>', bold=True) + '  admin (&).',
        H('@spawn copy prop <world:id|n>', bold=True) + '  admin (&).',
        '  Copies a template from another world into this world.',
        '  n = result number from your last @spawn list.',
        '  Example: @spawn list npcs goblin --all  then  @spawn copy npc 3',
        '  Example: @spawn copy npc cyberpunk_darknet:7',
    ]
    T['@generate'] = T['@gen'] = [
        H('@generate', bold=True) + ' — procedurally generate rooms from a theme.',
        '',
        H('@generate preview <theme> <size> <difficulty> [seed:N]', bold=True),
        '  Show what would be generated without committing.  halfop (%).',
        '',
        H('@generate area <theme> <size> <difficulty> [dir] [seed:N]', bold=True),
        '  Generate and attach a new area.  op (@).',
        '  size: micro (2-3)  small (4-6)  medium (7-12)',
        '  difficulty: easy  medium  hard  mixed',
        '  dir: direction from current room (auto-picked if omitted)',
        '  seed: reproduce a previous generation exactly',
        '  Example: @generate area dungeon small hard north seed:4721',
        '',
        H('@generate room <type> <theme>', bold=True),
        '  Generate and attach a single room.  op (@).',
        '  type hint (chamber, corridor, boss_room etc.) names the room.',
        '  Example: @generate room boss_room crypt',
    ]
    T['@list'] = [
        H('@list', bold=True) + ' — list world objects.  halfop (%).',
        '',
        H('@list rooms', bold=True) + '  — all rooms with ID and safe status.',
        H('@list npcs [query]', bold=True) + '  — NPC templates (partial name search).',
        H('@list items [query]', bold=True) + '  — item templates.',
        H('@list bans', bold=True) + '  — world ban list.',
        H('@list players [all]', bold=True) + '  — online players (all = ever created).',
        H('@list themes', bold=True) + '  — generation themes.',
        H('@list quests', bold=True) + '  — quest definitions.',
    ]
    T['@create'] = [
        H('@create', bold=True) + ' — create world objects.',
        '',
        H('@create room <dir> [name]', bold=True) + '  — create a new room attached to '
        'the current room in direction <dir>.  op (@).',
        '  Bidirectional exit created automatically. You are moved into the new room.',
        '  Example: @create room north "The Watchtower"',
        '',
        H('@create npc <name>', bold=True) + '  — create a new NPC template.  admin (&).',
        '',
        H('@create theme <name>', bold=True) + '  — create a new generation theme.  admin (&).',
    ]
    T['@attach'] = [
        H('@attach <room_id> <direction>', bold=True) + '  — wire a bidirectional exit from '
        'the current room to <room_id> in <direction>.  op (@).',
        '  The reverse exit (opposite direction → current room) is also created.',
        H('@attach <room_id> <dir> --oneway', bold=True) + '  — one-directional only.',
        '  Example: @attach 14 north',
    ]
    T['@modify'] = [
        H('@modify', bold=True) + ' — edit world objects (thin wrapper over legacy commands).',
        '',
        H('@modify room <desc|name|exit|safe> [...]', bold=True) + '  op (@).',
        '  Same as @room.  Operates on your current room.  Type %s for full syntax.' % H('help @room', bold=True),
        H('@modify npc <...>', bold=True) + '  — same as @npc.  admin (&).',
        '  Type %s for full syntax.' % H('help @npc', bold=True),
        H('@modify player <nick> <field> <value>', bold=True) + '  admin (&).',
        '  Type %s for field list.' % H('help @player', bold=True),
        H('@modify world <subcommand>', bold=True) + '  admin (&).',
        '  Type %s for subcommands and overview.' % H('help @world', bold=True),
    ]
    T['guild'] = [
        H('guild', bold=True) + ' — show available guilds or switch to a new guild.',
        '',
        H('guild', bold=True) + '  — list available guilds for this world.',
        H('guild <name>', bold=True) + '  — switch to the named guild.',
        '  Guild changes are free and permanent. All previously earned skills are kept.',
        '  You can also trigger this via a Guild Master NPC:',
        '  talk <guildmaster>  then  guild <name>',
    ]
    T['@theme'] = [
        H('@theme', bold=True) + ' — manage generation themes.',
        '',
        H('@theme create <name>', bold=True) + '  admin (&).',
        '',
        H('@theme fragments <theme> <atmosphere|structure|detail>', bold=True),
        '  List fragments.  halfop (%).',
        H('@theme fragment <theme> <type> :<text>', bold=True) + '  — add.  admin (&).',
        H('@theme fragment <theme> <type> <n> :<text>', bold=True) + '  — edit.  admin (&).',
        H('@theme fragment <theme> <type> del <n>', bold=True) + '  — delete.  admin (&).',
        H('@theme fragment <theme> <type> test', bold=True)
            + '  — preview samples.  halfop (%).',
        '',
        H('@theme words <theme> <adjective|noun>', bold=True) + '  list.  halfop (%).',
        H('@theme word <theme> <type> :<text>', bold=True) + '  add.  admin (&).',
        H('@theme word <theme> <type> del <n>', bold=True) + '  delete.  admin (&).',
        '',
        H('@theme npc <theme> tier:<n> :<name>', bold=True) + '  add to pool.  admin (&).',
        H('@theme npc <theme> del <n>', bold=True) + '  remove.  admin (&).',
        H('@theme loot <theme> :<item> weight:<n>', bold=True) + '  add.  admin (&).',
        H('@theme loot <theme> del <n>', bold=True) + '  remove.  admin (&).',
        H('@theme ambient <theme> :<text>', bold=True) + '  add flavor string.  admin (&).',
        H('@theme ambient <theme> del <n>', bold=True) + '  remove.  admin (&).',
    ]
    T['@difficulty'] = [
        H('@difficulty', bold=True) + ' — tune the XP curve.  Requires owner (~).',
        '',
        H('@difficulty', bold=True) + '  — show a kill-count table for every NPC in this world',
        '  that awards XP, ordered from weakest to strongest.',
        H('@difficulty <count>', bold=True) + '  — set difficulty so that killing <count> of',
        '  the highest-XP NPC in this world is enough to reach level 32.',
        '  Adjusts the per-world XP scaling factor and persists it across restarts.',
        '  Example: @difficulty 1     (one top-tier kill reaches the cap)',
        '  Example: @difficulty 100   (a hundred top-tier kills reaches the cap)',
    ]


# ---------------------------------------------------------------------------
# Procedural generation helpers
# ---------------------------------------------------------------------------

_OPPOSITE  = {'north': 'south', 'south': 'north',
               'east':  'west',  'west':  'east',
               'up':    'down',  'down':  'up'}
_CARDINALS = ['north', 'south', 'east', 'west']


_RTYPE_PREFIX = {
    'shrine':           'Shrine of the',
    'armory':           'Armory of the',
    'boss_antechamber': 'Antechamber of the',
    'boss_room':        'Lair of the',
    'treasure':         'Vault of the',
    'junction':         'Crossroads of the',
}


def _gen_room_name(rng, adjs, nouns, rtype=None):
    noun = rng.choice(nouns) if nouns else 'Chamber'
    if adjs:
        base = ('%s %s' % (rng.choice(adjs), noun)).title()
    else:
        base = noun.title()
    prefix = _RTYPE_PREFIX.get(rtype or '')
    if prefix:
        return '%s %s' % (prefix, base)
    return base


def _make_gen_net():
    """
    Build a fresh MarkovNet for procedural area generation room-type sequencing.

    Each node is a Func whose callable returns the room-type name as a string.
    Markov transitions encode spatial narrative coherence: boss rooms lead to
    wind-down rooms (shrine, corridor, treasure), never to another boss room.
    The net is used statelessly — one fresh instance per @generate invocation —
    and the resulting room-type sequence is persisted to sqlite as room names.
    """
    def _rtype(name):
        def fn(*_a, **_kw): return name
        fn.__name__ = name
        return fn

    entrance  = Func(_rtype('entrance'),         P=0.2)
    corridor  = Func(_rtype('corridor'),         P=1.0)
    junction  = Func(_rtype('junction'),         P=0.5)
    chamber   = Func(_rtype('chamber'),          P=0.8)
    shrine    = Func(_rtype('shrine'),           P=0.4)
    armory    = Func(_rtype('armory'),           P=0.4)
    boss_ante = Func(_rtype('boss_antechamber'), P=0.2)
    boss_room = Func(_rtype('boss_room'),        P=0.15)
    treasure  = Func(_rtype('treasure'),         P=0.3)

    corridor.update( {corridor: 40, chamber: 30, junction: 15, armory: 10, shrine: 5})
    junction.update( {corridor: 35, chamber: 25, shrine: 15,  armory: 15, boss_ante: 10})
    chamber.update(  {corridor: 30, chamber: 20, armory: 15,  shrine: 15, boss_ante: 10, treasure: 10})
    shrine.update(   {corridor: 40, chamber: 30, shrine: 10,  junction: 20})
    armory.update(   {corridor: 35, chamber: 30, shrine: 15,  junction: 15, boss_ante: 5})
    boss_ante.update({boss_room: 60, corridor: 20, shrine: 20})
    boss_room.update({corridor: 50, shrine: 30, treasure: 20})   # wind-down only
    treasure.update( {corridor: 50, shrine: 30, chamber: 20})
    entrance.update( {corridor: 60, chamber: 25, junction: 15})

    return MarkovNet(corridor, junction, chamber, shrine, armory,
                     boss_ante, boss_room, treasure, entrance)


def _gen_room_desc(rng, atm, struct, detail, ambient):
    parts = []
    if atm:    parts.append(rng.choice(atm))
    if struct: parts.append(rng.choice(struct))
    if detail and rng.random() < 0.7:
        parts.append(rng.choice(detail))
    if ambient and rng.random() < 0.4:
        parts.insert(0, rng.choice(ambient))
    return '  '.join(parts) if parts else 'A nondescript space.'


def _admin_generate(client, channel, world, player,
                    theme_name, size, difficulty,
                    attach_dir, seed_val, preview=False):
    """
    Procedural area generator.  preview=True shows planned output
    without committing to sqlite.
    """
    theme_row = world.db.execute(
        'SELECT 1 FROM themes WHERE theme_name=? AND world=?',
        (theme_name, world.world_name)
    ).fetchone()
    if not theme_row:
        msg(client, channel,
            'Theme "%s" not found. Create it with: @theme create %s' % (
                theme_name, theme_name), C.SYSTEM)
        return False

    def _frags(ftype):
        return [r['text'] for r in world.db.execute(
            'SELECT text FROM theme_fragments '
            'WHERE theme=? AND world=? AND frag_type=?',
            (theme_name, world.world_name, ftype)
        ).fetchall()]

    def _words(wtype):
        return [r['text'] for r in world.db.execute(
            'SELECT text FROM theme_words '
            'WHERE theme=? AND world=? AND word_type=?',
            (theme_name, world.world_name, wtype)
        ).fetchall()]

    atm     = _frags('atmosphere')
    struct  = _frags('structure')
    detail  = _frags('detail')
    adjs    = _words('adjective')
    nouns   = _words('noun')
    ambient = [r['text'] for r in world.db.execute(
        'SELECT text FROM theme_ambient WHERE theme=? AND world=?',
        (theme_name, world.world_name)
    ).fetchall()]
    npc_rows = world.db.execute(
        'SELECT npc_name, danger_tier FROM theme_npcs WHERE theme=? AND world=?',
        (theme_name, world.world_name)
    ).fetchall()

    tier_ranges = {'easy': (1, 1), 'medium': (1, 2),
                   'hard': (2, 3), 'mixed':  (1, 3)}
    tier_min, tier_max = tier_ranges.get(difficulty, (1, 2))
    eligible = [r for r in npc_rows
                if tier_min <= r['danger_tier'] <= tier_max]

    size_ranges = {'micro': (2, 3), 'small': (4, 6), 'medium': (7, 12), 'large': (20, 30)}
    lo, hi = size_ranges.get(size, (4, 6))

    actual_seed = seed_val if seed_val is not None else random.randint(1000, 99999)
    rng = random.Random(actual_seed)
    room_count = rng.randint(lo, hi)

    # MarkovNet room-type sequencing for spatial narrative coherence.
    gen_net    = _make_gen_net()
    room_types = [gen_net() for _ in range(room_count)]

    # ProbDist NPC spawn selection, weighted by tier position within the difficulty range.
    npc_dist = None
    if eligible:
        npc_weights = {}
        for n in eligible:
            w = max(1, (n['danger_tier'] - tier_min + 1) * 10)
            npc_weights[n['npc_name']] = npc_weights.get(n['npc_name'], 0) + w
        npc_dist = ProbDist(npc_weights)

    rooms_data = []
    for rtype in room_types:
        name   = _gen_room_name(rng, adjs, nouns, rtype)
        desc   = _gen_room_desc(rng, atm, struct, detail, ambient)
        spawns = []
        if rtype == 'boss_room':
            boss_npc = world.db.execute(
                'SELECT name FROM npcs WHERE world=? AND danger_tier=4 '
                'ORDER BY RANDOM() LIMIT 1',
                (world.world_name,)
            ).fetchone()
            if boss_npc:
                spawns.append(boss_npc['name'])
            elif npc_dist:
                spawns.append(npc_dist.pick)
        elif npc_dist and rng.random() < 0.7:
            spawns.append(npc_dist.pick)
            if len(eligible) > 1 and rng.random() < 0.3:
                spawns.append(npc_dist.pick)
        rooms_data.append({'type': rtype, 'name': name, 'description': desc, 'npcs': spawns})

    if preview:
        msg(client, channel,
            paint('Preview: %s / %s / %s — %d rooms  (seed %d)' % (
                theme_name, size, difficulty, room_count, actual_seed),
                bold=True), C.SYSTEM)
        for i, rd in enumerate(rooms_data):
            msg(client, channel,
                '  [%d] [%s] %s' % (i + 1, rd['type'], paint(rd['name'], bold=True)))
            msg(client, channel, '      %s' % rd['description'])
            if rd['npcs']:
                msg(client, channel,
                    '      NPCs: ' + ', '.join(rd['npcs']), C.SYSTEM)
        msg(client, channel,
            "To commit: @generate area %s %s %s seed:%d" % (
                theme_name, size, difficulty, actual_seed), C.SYSTEM)
        return True

    # Determine attach direction
    cur_room       = world.get_room(player['room_id'])
    existing_exits = cur_room.get('exits', {}) if cur_room else {}
    if attach_dir and attach_dir in _OPPOSITE:
        entry_dir = attach_dir
    else:
        free = [d for d in _CARDINALS if d not in existing_exits]
        if not free:
            msg(client, channel,
                'No free cardinal exits from this room. Specify a direction: '
                '@generate area <theme> <size> <difficulty> <dir>', C.SYSTEM)
            return False
    entry_dir = attach_dir if (attach_dir and attach_dir in _OPPOSITE) else free[0]
    back_dir  = _OPPOSITE[entry_dir]

    # Insert rooms
    new_ids = []
    for rd in rooms_data:
        cur2 = world.db.execute(
            'INSERT INTO rooms (world, name, description, exits, props, is_safe) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (world.world_name, rd['name'], rd['description'], '{}', '{}', 0)
        )
        new_ids.append(cur2.lastrowid)

    # Wire exits — chain with back-links; first room links back to current room
    for i, rid in enumerate(new_ids):
        exits = {}
        exits[back_dir] = player['room_id'] if i == 0 else new_ids[i - 1]
        if i < len(new_ids) - 1:
            exits[entry_dir] = new_ids[i + 1]
        world.db.execute(
            'UPDATE rooms SET exits=? WHERE room_id=?',
            (json.dumps(exits), rid)
        )

    # Attach current room → first new room
    updated_exits = dict(existing_exits)
    updated_exits[entry_dir] = new_ids[0]
    world.db.execute(
        'UPDATE rooms SET exits=? WHERE room_id=?',
        (json.dumps(updated_exits), player['room_id'])
    )

    # Spawn NPCs
    now_f = time.time()
    for i, rd in enumerate(rooms_data):
        rid = new_ids[i]
        for npc_name in rd['npcs']:
            nrow = world.db.execute(
                'SELECT npc_id, stats FROM npcs '
                'WHERE world=? AND LOWER(name) LIKE ? LIMIT 1',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if nrow:
                max_b = json.loads(nrow['stats'] or '{}').get('max_blood', 10)
                world.db.execute(
                    'INSERT INTO npc_instances '
                    '  (npc_id, world, room_id, spawn_room_id, current_blood, '
                    '   state, next_action_at) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (nrow['npc_id'], world.world_name, rid, rid,
                     max_b, 'idle', now_f + 30.0)
                )

    world.commit()
    msg(client, channel,
        paint('Generated:', bold=True) +
        ' %d rooms attached %s from here.  Entrance: %s.  Seed: %d' % (
            room_count, entry_dir, rooms_data[0]['name'], actual_seed),
        C.SYSTEM)
    msg(client, channel,
        "  Reproduce: @generate area %s %s %s seed:%d" % (
            theme_name, size, difficulty, actual_seed), C.SYSTEM)
    return True


# ---------------------------------------------------------------------------
# Admin command router
# ---------------------------------------------------------------------------

def _cmd_admin(client, channel, world, player, command, args):
    """Admin command router. Requires at least halfop (+h)."""
    tier = _admin_tier(client.nick, channel)
    if tier < 1:
        msg(client, channel,
            'Admin commands require at least halfop (+h).', C.SYSTEM)
        return

    sub  = args.split(None, 1)[0].lower() if args else ''
    rest = args.split(None, 1)[1] if args and ' ' in args else ''

    # ── @npc — NPC template editor ────────────────────────────────────────
    if command == 'npc':
        if tier < 3:
            msg(client, channel,
                '@npc requires admin (&) or owner (~).', C.SYSTEM)
            return

        if not sub or sub == 'list':
            rows = world.db.execute(
                'SELECT npc_id, name, behavior, danger_tier, autoplay_mode, autoplay_target '
                'FROM npcs WHERE world=? ORDER BY name',
                (world.world_name,)
            ).fetchall()
            if not rows:
                msg(client, channel, 'No NPC templates in this world.', C.SYSTEM)
                return
            msg(client, channel, paint('NPC templates:', bold=True), C.SYSTEM)
            for r in rows:
                ap = r['autoplay_mode']
                ap_str = ''
                if ap:
                    ap_str = '  autoplay:%s' % ap
                    if r['autoplay_target']:
                        ap_str += '(%s)' % r['autoplay_target']
                msg(client, channel,
                    '  [%d] %s  tier:%d  behavior:%s%s' % (
                        r['npc_id'], r['name'],
                        r['danger_tier'], r['behavior'], ap_str), C.SYSTEM)
            return

        if sub == 'show':
            npc_name = rest.strip()
            if not npc_name:
                msg(client, channel, 'Usage: @npc show <name>', C.SYSTEM)
                return
            row = world.db.execute(
                'SELECT * FROM npcs WHERE world=? AND LOWER(name) LIKE ?',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if not row:
                msg(client, channel, 'No NPC matching "%s".' % npc_name, C.SYSTEM)
                return
            d = json.loads(row['dialogue'] or '{}')
            msg(client, channel,
                paint('[%d] %s' % (row['npc_id'], row['name']), bold=True),
                C.SYSTEM)
            msg(client, channel,
                '  greeting: ' + paint(d.get('greeting', '(none)'), bold=True),
                C.SYSTEM)
            topics = d.get('topics', {})
            if topics:
                for k, v in topics.items():
                    msg(client, channel,
                        '  topic %s: %s' % (paint(k, bold=True), v), C.SYSTEM)
            else:
                msg(client, channel, '  (no topics)', C.SYSTEM)
            msg(client, channel,
                '  default: ' + paint(d.get('default', '(none)'), bold=True),
                C.SYSTEM)
            return

        if sub == 'add':
            npc_name = rest.strip()
            if not npc_name:
                msg(client, channel, 'Usage: @npc add <name>', C.SYSTEM)
                return
            cur = world.db.execute(
                'INSERT INTO npcs '
                '  (world, name, description, danger_tier, behavior, '
                '   stats, loot, respawn_delay, dialogue) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (world.world_name, npc_name, 'A mysterious figure.',
                 1, 'idle',
                 json.dumps({'max_blood': 20, 'attack': 2,
                             'defense': 0, 'attack_speed': 3.0}),
                 '[]', 120, '{}')
            )
            npc_id  = cur.lastrowid
            room_id = player['room_id']
            world.db.execute(
                'INSERT INTO npc_instances '
                '  (npc_id, world, room_id, spawn_room_id, current_blood, '
                '   state, next_action_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (npc_id, world.world_name, room_id, room_id,
                 20, 'idle', time.time() + 5.0)
            )
            world.commit()
            msg(client, channel,
                'Created %s [id %d] and spawned here. '
                'Edit with @npc setgreeting/addtopic/setbehavior.' % (
                    paint(npc_name, bold=True), npc_id), C.SYSTEM)
            return

        if sub == 'setgreeting':
            parts2 = rest.split(None, 1)
            if len(parts2) < 2:
                msg(client, channel,
                    'Usage: @npc setgreeting <name> <text>', C.SYSTEM)
                return
            npc_name, text = parts2[0], parts2[1]
            row = world.db.execute(
                'SELECT npc_id, dialogue FROM npcs '
                'WHERE world=? AND LOWER(name) LIKE ?',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if not row:
                msg(client, channel,
                    'No NPC matching "%s".' % npc_name, C.SYSTEM)
                return
            d = json.loads(row['dialogue'] or '{}')
            d['greeting'] = text
            world.db.execute(
                'UPDATE npcs SET dialogue=? WHERE npc_id=?',
                (json.dumps(d), row['npc_id'])
            )
            world.commit()
            msg(client, channel,
                'Greeting updated for NPC %d.' % row['npc_id'], C.SYSTEM)
            return

        if sub == 'addtopic':
            parts2 = rest.split(None, 2)
            if len(parts2) < 3:
                msg(client, channel,
                    'Usage: @npc addtopic <name> <key> <text>', C.SYSTEM)
                return
            npc_name, key, text = parts2[0], parts2[1].lower(), parts2[2]
            row = world.db.execute(
                'SELECT npc_id, dialogue FROM npcs '
                'WHERE world=? AND LOWER(name) LIKE ?',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if not row:
                msg(client, channel,
                    'No NPC matching "%s".' % npc_name, C.SYSTEM)
                return
            d = json.loads(row['dialogue'] or '{}')
            d.setdefault('topics', {})[key] = text
            world.db.execute(
                'UPDATE npcs SET dialogue=? WHERE npc_id=?',
                (json.dumps(d), row['npc_id'])
            )
            world.commit()
            msg(client, channel,
                'Topic "%s" set on NPC %d.' % (key, row['npc_id']), C.SYSTEM)
            return

        if sub == 'deltopic':
            parts2 = rest.split(None, 1)
            if len(parts2) < 2:
                msg(client, channel,
                    'Usage: @npc deltopic <name> <key>', C.SYSTEM)
                return
            npc_name, key = parts2[0], parts2[1].lower()
            row = world.db.execute(
                'SELECT npc_id, dialogue FROM npcs '
                'WHERE world=? AND LOWER(name) LIKE ?',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if not row:
                msg(client, channel,
                    'No NPC matching "%s".' % npc_name, C.SYSTEM)
                return
            d = json.loads(row['dialogue'] or '{}')
            topics = d.get('topics', {})
            if key not in topics:
                msg(client, channel,
                    'Topic "%s" not found on that NPC.' % key, C.SYSTEM)
                return
            del topics[key]
            world.db.execute(
                'UPDATE npcs SET dialogue=? WHERE npc_id=?',
                (json.dumps(d), row['npc_id'])
            )
            world.commit()
            msg(client, channel,
                'Topic "%s" removed from NPC %d.' % (key, row['npc_id']),
                C.SYSTEM)
            return

        if sub == 'setdefault':
            parts2 = rest.split(None, 1)
            if len(parts2) < 2:
                msg(client, channel,
                    'Usage: @npc setdefault <name> <text>', C.SYSTEM)
                return
            npc_name, text = parts2[0], parts2[1]
            row = world.db.execute(
                'SELECT npc_id, dialogue FROM npcs '
                'WHERE world=? AND LOWER(name) LIKE ?',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if not row:
                msg(client, channel,
                    'No NPC matching "%s".' % npc_name, C.SYSTEM)
                return
            d = json.loads(row['dialogue'] or '{}')
            d['default'] = text
            world.db.execute(
                'UPDATE npcs SET dialogue=? WHERE npc_id=?',
                (json.dumps(d), row['npc_id'])
            )
            world.commit()
            msg(client, channel,
                'Default response updated for NPC %d.' % row['npc_id'],
                C.SYSTEM)
            return

        if sub == 'setbehavior':
            parts2 = rest.split(None, 1)
            if len(parts2) < 2:
                msg(client, channel,
                    'Usage: @npc setbehavior <name> '
                    '<passive|aggressive|aggressive_talker|patrol|idle>',
                    C.SYSTEM)
                return
            npc_name, beh = parts2[0], parts2[1].strip().lower()
            valid = {'passive', 'aggressive', 'aggressive_talker', 'patrol', 'idle'}
            if beh not in valid:
                msg(client, channel,
                    'Valid behaviors: %s' % ', '.join(sorted(valid)), C.SYSTEM)
                return
            row = world.db.execute(
                'SELECT npc_id FROM npcs WHERE world=? AND LOWER(name) LIKE ?',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if not row:
                msg(client, channel,
                    'No NPC matching "%s".' % npc_name, C.SYSTEM)
                return
            world.db.execute(
                'UPDATE npcs SET behavior=? WHERE npc_id=?',
                (beh, row['npc_id'])
            )
            world.commit()
            msg(client, channel,
                'Behavior set to "%s" on NPC %d.' % (beh, row['npc_id']),
                C.SYSTEM)
            return

        if sub == 'setautoplay':
            parts2 = rest.split(None, 1)
            if len(parts2) < 2:
                msg(client, channel,
                    'Usage: @npc setautoplay <name> <mode|off>  '
                    '[target filter for grinder mode]', C.SYSTEM)
                return
            npc_name  = parts2[0]
            mode_args = parts2[1].strip().split(None, 1)
            mode_val  = mode_args[0].lower()
            ap_target = mode_args[1].strip() if len(mode_args) > 1 else None
            valid_ap  = set(_AUTOPLAY_MODES) | {'off'}
            if mode_val not in valid_ap:
                msg(client, channel,
                    'Valid modes: off  ' + '  '.join(_AUTOPLAY_MODES), C.SYSTEM)
                return
            nrow = world.db.execute(
                'SELECT npc_id, name, danger_tier, behavior, dialogue '
                'FROM npcs WHERE world=? AND LOWER(name) LIKE ?',
                (world.world_name, '%' + npc_name.lower() + '%')
            ).fetchone()
            if not nrow:
                msg(client, channel,
                    'No NPC matching "%s".' % npc_name, C.SYSTEM)
                return
            if mode_val != 'off':
                if nrow['danger_tier'] >= 4:
                    msg(client, channel,
                        'Tier-4 boss NPCs cannot use autoplay.', C.SYSTEM)
                    return
                if nrow['behavior'] == 'aggressive_talker':
                    msg(client, channel,
                        'aggressive_talker NPCs cannot use autoplay.', C.SYSTEM)
                    return
                # Role NPC warning for movement modes.
                if mode_val not in ('passive', 'defender'):
                    dlg = json.loads(nrow['dialogue'] or '{}')
                    if _npc_is_role(dlg):
                        msg(client, channel,
                            paint('Warning:', bold=True, color=C.SYSTEM) +
                            ' %s has vendor/mission/guild dialogue topics. '
                            'A movement autoplay mode may displace it from its '
                            'role. Set anyway? Re-run the command to confirm.' % nrow['name'],
                            C.SYSTEM)
                        # Use a one-shot confirm key in world state.
                        key = '_ap_warn_%d' % nrow['npc_id']
                        if not world._buffs.get(key):
                            world._buffs[key] = {'expires_at': time.time() + 30}
                            return
                        world._buffs.pop(key, None)
            world.db.execute(
                'UPDATE npcs SET autoplay_mode=?, autoplay_target=? WHERE npc_id=?',
                (mode_val if mode_val != 'off' else None,
                 ap_target if mode_val not in ('off', 'passive', 'defender') else None,
                 nrow['npc_id'])
            )
            world.commit()
            if mode_val == 'off':
                _autoplay_state  = {k: v for k, v in _autoplay_state.items()
                                    if k != ('npc',)}  # can't know iid here; instances reset on next tick
                msg(client, channel,
                    'Autoplay cleared on %s (npc_id %d).' % (
                        nrow['name'], nrow['npc_id']), C.SYSTEM)
            else:
                detail = (' target: ' + ap_target) if ap_target else ''
                msg(client, channel,
                    'Autoplay set to %s%s on %s (npc_id %d).' % (
                        paint(mode_val, bold=True, color=C.SAFE),
                        detail, nrow['name'], nrow['npc_id']), C.SYSTEM)
            return

        msg(client, channel, paint('@npc subcommands:', bold=True), C.SYSTEM)
        for line in [
            '  @npc list                                  — list all NPC templates',
            '  @npc show <name>                           — dump dialogue',
            '  @npc add <name>                            — create NPC here',
            '  @npc setgreeting <name> <text>             — set greeting line',
            '  @npc addtopic <name> <key> <text>          — add/replace a topic',
            '  @npc deltopic <name> <key>                 — remove a topic',
            '  @npc setdefault <name> <text>              — set default response',
            '  @npc setbehavior <name> <behavior>         — change NPC behavior',
            '  @npc setautoplay <name> <mode|off>         — set autoplay mode',
            '    modes: passive  defender  skirmisher  explorer  hunter  grinder',
            '    grinder: @npc setautoplay <name> grinder <target filter>',
            '  Special topic values: __vendor__  __mission__:<quest_id>',
        ]:
            msg(client, channel, line, C.SYSTEM)
        return

    # ── @announce ─────────────────────────────────────────────────────────
    if command == 'announce':
        if tier < 2:
            msg(client, channel,
                '@announce requires op (@) or above.', C.SYSTEM)
            return
        text = args.strip()
        if not text:
            msg(client, channel, 'Usage: @announce <text>', C.SYSTEM)
            return
        label = paint('[Announcement]', bold=True)
        for c in list(channel.clients):
            if c.nick in world._online:
                msg(c, channel, label + ' ' + text, C.SYSTEM)
        return

    # ── @goto ─────────────────────────────────────────────────────────────
    if command == 'goto':
        if tier < 2:
            msg(client, channel, '@goto requires op (@) or above.', C.SYSTEM)
            return
        target = args.strip()
        if not target:
            msg(client, channel, 'Usage: @goto <room_name|nick>', C.SYSTEM)
            return
        target_l = target.lower()
        # Try a player nick first.
        for p in world.online_players():
            if target_l in p['nick'].lower():
                world.update_player(client.nick, room_id=p['room_id'])
                world.commit()
                msg(client, channel,
                    'Teleported to %s.' % paint(p['nick'], bold=True),
                    C.SYSTEM)
                _show_room(client, channel, world, p['room_id'])
                return
        # Fall back to room name.
        row = world.db.execute(
            'SELECT room_id, name FROM rooms '
            'WHERE world=? AND LOWER(name) LIKE ? ORDER BY room_id LIMIT 1',
            (world.world_name, '%' + target_l + '%')
        ).fetchone()
        if row:
            world.update_player(client.nick, room_id=row['room_id'])
            world.commit()
            msg(client, channel,
                'Teleported to %s.' % paint(row['name'], bold=True), C.SYSTEM)
            _show_room(client, channel, world, row['room_id'])
            return
        msg(client, channel,
            'No room or player matching "%s".' % target, C.SYSTEM)
        return

    # ── @rooms ────────────────────────────────────────────────────────────
    if command == 'rooms':
        rows = world.db.execute(
            'SELECT room_id, name, is_safe FROM rooms '
            'WHERE world=? ORDER BY room_id',
            (world.world_name,)
        ).fetchall()
        if not rows:
            msg(client, channel, 'No rooms in this world.', C.SYSTEM)
            return
        msg(client, channel, paint('Rooms:', bold=True), C.SYSTEM)
        for r in rows:
            safe = paint(' [safe]', color=C.SAFE) if r['is_safe'] else ''
            msg(client, channel,
                '  [%d] %s%s' % (r['room_id'], r['name'], safe), C.SYSTEM)
        return

    # ── @room ─────────────────────────────────────────────────────────────
    if command == 'room':
        if tier < 2:
            msg(client, channel, '@room requires op (@) or above.', C.SYSTEM)
            return
        room = world.get_room(player['room_id'])
        if room is None:
            msg(client, channel, 'You are not in a valid room.', C.SYSTEM)
            return

        if sub == 'desc':
            text = rest.strip()
            if not text:
                msg(client, channel, 'Usage: @room desc <text>', C.SYSTEM)
                return
            world.db.execute(
                'UPDATE rooms SET description=? WHERE room_id=? AND world=?',
                (text, room['room_id'], world.world_name)
            )
            world.commit()
            msg(client, channel, 'Room description updated.', C.SYSTEM)
            return

        if sub == 'name':
            text = rest.strip()
            if not text:
                msg(client, channel, 'Usage: @room name <text>', C.SYSTEM)
                return
            world.db.execute(
                'UPDATE rooms SET name=? WHERE room_id=? AND world=?',
                (text, room['room_id'], world.world_name)
            )
            world.commit()
            msg(client, channel,
                'Room renamed to %s.' % paint(text, bold=True), C.SYSTEM)
            return

        if sub == 'exit':
            parts2 = rest.split(None, 1)
            if len(parts2) < 2:
                msg(client, channel,
                    'Usage: @room exit <direction> <room_name|id>', C.SYSTEM)
                return
            direction = parts2[0].lower()
            full_dir  = _DIR_FULL.get(direction, direction)
            if full_dir not in _OPPOSITE:
                msg(client, channel,
                    'Unknown direction "%s". Use: '
                    'north south east west up down' % direction, C.SYSTEM)
                return
            dest_query = parts2[1].strip()
            if dest_query.isdigit():
                dest_row = world.db.execute(
                    'SELECT room_id, name FROM rooms '
                    'WHERE room_id=? AND world=?',
                    (int(dest_query), world.world_name)
                ).fetchone()
            else:
                dest_row = world.db.execute(
                    'SELECT room_id, name FROM rooms '
                    'WHERE world=? AND LOWER(name) LIKE ? '
                    'ORDER BY room_id LIMIT 1',
                    (world.world_name, '%' + dest_query.lower() + '%')
                ).fetchone()
            if not dest_row:
                msg(client, channel,
                    'No room matching "%s".' % dest_query, C.SYSTEM)
                return
            exits = dict(room.get('exits', {}))
            exits[full_dir] = dest_row['room_id']
            world.db.execute(
                'UPDATE rooms SET exits=? WHERE room_id=? AND world=?',
                (json.dumps(exits), room['room_id'], world.world_name)
            )
            world.commit()
            msg(client, channel,
                'Exit %s → %s [%d] added.' % (
                    paint(full_dir, underline=True),
                    paint(dest_row['name'], bold=True),
                    dest_row['room_id']), C.SYSTEM)
            return

        if sub == 'safe':
            val = 1 if rest.strip().lower() in ('on', '1', 'true', 'yes') else 0
            world.db.execute(
                'UPDATE rooms SET is_safe=? WHERE room_id=? AND world=?',
                (val, room['room_id'], world.world_name)
            )
            world.commit()
            msg(client, channel,
                'Room is_safe set to %s.' % ('on' if val else 'off'), C.SYSTEM)
            return

        msg(client, channel,
            'Usage: @room desc <text>  |  @room name <text>  |  '
            '@room exit <dir> <room>  |  @room safe on/off', C.SYSTEM)
        return

    # ── @who (admin version) ──────────────────────────────────────────────
    if command == 'who':
        if sub == 'all':
            rows = world.db.execute(
                'SELECT nick, level, guild, room_id, blood, max_blood, '
                '       stamina, max_stamina, last_seen, is_frozen '
                'FROM players WHERE world=? ORDER BY last_seen DESC',
                (world.world_name,)
            ).fetchall()
            if not rows:
                msg(client, channel,
                    'No players recorded in this world.', C.SYSTEM)
                return
            msg(client, channel,
                paint('All players (most recent first):', bold=True), C.SYSTEM)
            for r in rows:
                guild  = (' ' + r['guild']) if r['guild'] else ''
                ts     = r['last_seen']
                age    = ('never' if ts is None
                          else '%dh ago' % int(
                              (time.time() - float(ts)) / 3600))
                frozen = paint(' [frozen]', color=C.SYSTEM) if r['is_frozen'] else ''
                msg(client, channel,
                    '  %s  lv%d%s  %s%s' % (
                        paint(r['nick'], bold=True),
                        r['level'], guild, age, frozen), C.SYSTEM)
            return
        online = world.online_players()
        if not online:
            msg(client, channel, 'No players currently online.', C.SYSTEM)
            return
        msg(client, channel, paint('Online players:', bold=True), C.SYSTEM)
        for p in online:
            room      = world.get_room(p['room_id']) if p.get('room_id') else None
            room_name = room['name'] if room else '?'
            guild     = (' ' + p['guild']) if p.get('guild') else ''
            b_pct     = int(100 * p['blood']   / max(1, p['max_blood']))
            s_pct     = int(100 * p['stamina'] / max(1, p['max_stamina']))
            frozen    = paint(' [frozen]', color=C.SYSTEM) if p.get('is_frozen') else ''
            fx_rows   = world.get_status_effects(nick=p['nick'])
            fx_str    = (' [' + ' '.join(r['effect'] for r in fx_rows) + ']'
                         if fx_rows else '')
            msg(client, channel,
                '  %s  lv%d%s  %s  blood:%d%%  stamina:%d%%%s%s' % (
                    paint(p['nick'], bold=True),
                    p['level'], guild, room_name,
                    b_pct, s_pct, frozen, fx_str), C.SYSTEM)
        return

    # ── @kick ─────────────────────────────────────────────────────────────
    if command == 'kick':
        if tier < 2:
            msg(client, channel, '@kick requires op (@) or above.', C.SYSTEM)
            return
        parts2 = args.split(None, 1)
        nick   = parts2[0] if parts2 else ''
        reason = parts2[1] if len(parts2) > 1 else 'Ejected by admin.'
        if not nick:
            msg(client, channel, 'Usage: @kick <nick> [reason]', C.SYSTEM)
            return
        if nick not in world._online:
            msg(client, channel,
                '%s is not online in this world.' % paint(nick, bold=True),
                C.SYSTEM)
            return
        world._online.discard(nick)
        world.update_player(nick, last_seen=time.time())
        world.commit()
        target_c = next(
            (c for c in channel.clients if c.nick == nick), None)
        if target_c:
            msg(target_c, channel,
                paint('You have been kicked from this world.', bold=True) +
                '  Reason: ' + reason, C.SYSTEM)
        msg(client, channel,
            '%s has been kicked.' % paint(nick, bold=True), C.SYSTEM)
        return

    # ── @ban ──────────────────────────────────────────────────────────────
    if command == 'ban':
        if sub == 'list':
            rows = world.db.execute(
                'SELECT nick, banned_by, reason, banned_at FROM world_bans '
                'WHERE world=? ORDER BY banned_at DESC',
                (world.world_name,)
            ).fetchall()
            if not rows:
                msg(client, channel, 'No world bans.', C.SYSTEM)
                return
            msg(client, channel, paint('World bans:', bold=True), C.SYSTEM)
            for r in rows:
                ts  = r['banned_at']
                age = ('?' if ts is None
                       else '%dh ago' % int(
                           (time.time() - float(ts)) / 3600))
                msg(client, channel,
                    '  %s  by %s  %s  reason: %s' % (
                        paint(r['nick'], bold=True),
                        r['banned_by'] or '?', age,
                        r['reason'] or '(none)'), C.SYSTEM)
            return
        if tier < 3:
            msg(client, channel,
                '@ban requires admin (&) or owner (~).', C.SYSTEM)
            return
        parts2 = args.split(None, 1)
        nick   = parts2[0] if parts2 else ''
        reason = parts2[1] if len(parts2) > 1 else None
        if not nick:
            msg(client, channel,
                'Usage: @ban <nick> [reason]  |  @ban list', C.SYSTEM)
            return
        world.db.execute(
            'INSERT OR REPLACE INTO world_bans '
            '  (nick, world, banned_by, reason, banned_at) '
            'VALUES (?, ?, ?, ?, ?)',
            (nick, world.world_name, client.nick, reason, time.time())
        )
        world._online.discard(nick)
        world.commit()
        target_c = next(
            (c for c in channel.clients if c.nick == nick), None)
        if target_c:
            msg(target_c, channel,
                paint('You have been banned from this world.', bold=True),
                C.SYSTEM)
        msg(client, channel,
            '%s has been banned.' % paint(nick, bold=True), C.SYSTEM)
        return

    # ── @unban ────────────────────────────────────────────────────────────
    if command == 'unban':
        if tier < 3:
            msg(client, channel,
                '@unban requires admin (&) or owner (~).', C.SYSTEM)
            return
        nick = args.strip()
        if not nick:
            msg(client, channel, 'Usage: @unban <nick>', C.SYSTEM)
            return
        world.db.execute(
            'DELETE FROM world_bans WHERE nick=? AND world=?',
            (nick, world.world_name)
        )
        world.commit()
        msg(client, channel,
            '%s has been unbanned.' % paint(nick, bold=True), C.SYSTEM)
        return

    # ── @freeze ───────────────────────────────────────────────────────────
    if command == 'freeze':
        if tier < 2:
            msg(client, channel,
                '@freeze requires op (@) or above.', C.SYSTEM)
            return
        nick = args.strip()
        if not nick:
            msg(client, channel, 'Usage: @freeze <nick>', C.SYSTEM)
            return
        if world.get_player(nick) is None:
            msg(client, channel,
                'No player named %s in this world.' % paint(nick, bold=True),
                C.SYSTEM)
            return
        world.update_player(nick, is_frozen=1)
        world.commit()
        target_c = next(
            (c for c in channel.clients if c.nick == nick), None)
        if target_c:
            msg(target_c, channel,
                paint('You have been frozen.', bold=True) +
                ' You cannot move or act.', C.SYSTEM)
        msg(client, channel,
            '%s is now frozen.' % paint(nick, bold=True), C.SYSTEM)
        return

    # ── @unfreeze ─────────────────────────────────────────────────────────
    if command == 'unfreeze':
        if tier < 2:
            msg(client, channel,
                '@unfreeze requires op (@) or above.', C.SYSTEM)
            return
        nick = args.strip()
        if not nick:
            msg(client, channel, 'Usage: @unfreeze <nick>', C.SYSTEM)
            return
        if world.get_player(nick) is None:
            msg(client, channel,
                'No player named %s in this world.' % paint(nick, bold=True),
                C.SYSTEM)
            return
        world.update_player(nick, is_frozen=0)
        world.commit()
        target_c = next(
            (c for c in channel.clients if c.nick == nick), None)
        if target_c:
            msg(target_c, channel,
                paint('You have been unfrozen.', bold=True), C.SYSTEM)
        msg(client, channel,
            '%s has been unfrozen.' % paint(nick, bold=True), C.SYSTEM)
        return

    # ── @player ───────────────────────────────────────────────────────────
    if command == 'player':
        if tier < 3:
            msg(client, channel,
                '@player requires admin (&) or owner (~).', C.SYSTEM)
            return
        parts2 = args.split(None, 2)
        if len(parts2) < 3:
            msg(client, channel,
                'Usage: @player <nick> <field> <value>  '
                'Fields: blood max_blood stamina max_stamina '
                'gold level xp guild room_id is_frozen is_dead',
                C.SYSTEM)
            return
        p_nick, field, value = parts2[0], parts2[1].lower(), parts2[2]
        int_fields = {'blood', 'max_blood', 'stamina', 'max_stamina',
                      'gold', 'level', 'xp', 'room_id', 'is_frozen', 'is_dead'}
        allowed = int_fields | {'guild'}
        if field not in allowed:
            msg(client, channel,
                'Unknown field "%s". Allowed: %s' % (
                    field, ', '.join(sorted(allowed))), C.SYSTEM)
            return
        if world.get_player(p_nick) is None:
            msg(client, channel,
                'No player named %s in this world.' % paint(p_nick, bold=True),
                C.SYSTEM)
            return
        if field in int_fields:
            try:
                value = int(value)
            except ValueError:
                msg(client, channel,
                    'Field "%s" requires an integer.' % field, C.SYSTEM)
                return
        world.update_player(p_nick, **{field: value})
        world.commit()
        msg(client, channel,
            '%s.%s = %s' % (paint(p_nick, bold=True), field,
                            paint(str(value), bold=True)), C.SYSTEM)
        return

    # ── @world ────────────────────────────────────────────────────────────
    if command == 'world':
        if tier < 3:
            msg(client, channel,
                '@world requires admin (&) or owner (~).', C.SYSTEM)
            return

        # No args — settings overview.
        if not sub:
            wrow = world.db.execute(
                'SELECT description, magic_name, magic_source, start_room_id, model_enabled '
                'FROM worlds WHERE world_name=?',
                (world.world_name,)
            ).fetchone()
            n_rooms   = world.db.execute(
                'SELECT COUNT(*) AS c FROM rooms WHERE world=?',
                (world.world_name,)).fetchone()['c']
            n_npcs    = world.db.execute(
                'SELECT COUNT(*) AS c FROM npcs WHERE world=?',
                (world.world_name,)).fetchone()['c']
            n_players = world.db.execute(
                'SELECT COUNT(*) AS c FROM players WHERE world=?',
                (world.world_name,)).fetchone()['c']
            n_bans    = world.db.execute(
                'SELECT COUNT(*) AS c FROM world_bans WHERE world=?',
                (world.world_name,)).fetchone()['c']
            n_quests  = world.db.execute(
                'SELECT COUNT(*) AS c FROM quests WHERE world=?',
                (world.world_name,)).fetchone()['c']
            n_themes  = world.db.execute(
                'SELECT COUNT(*) AS c FROM themes WHERE world=?',
                (world.world_name,)).fetchone()['c']
            start_row = world.db.execute(
                'SELECT name FROM rooms WHERE room_id=?',
                (wrow['start_room_id'],)).fetchone() if wrow['start_room_id'] else None
            start_label = ('%d — %s' % (wrow['start_room_id'], start_row['name'])
                           if start_row else str(wrow['start_room_id']))

            msg(client, channel,
                paint('World: %s' % world.world_name, bold=True), C.SYSTEM)
            msg(client, channel,
                '  description:  %s' % (wrow['description'] or '(none)'), C.SYSTEM)
            msg(client, channel,
                '  magic_name:   %s    (@world magic_name <name>)' % (
                    wrow['magic_name'] or '(none)'), C.SYSTEM)
            msg(client, channel,
                '  magic_source: %s    (@world magic_source levelup|item|vendor)' % (
                    wrow['magic_source'] or '(none)'), C.SYSTEM)
            msg(client, channel,
                '  xp_factor:    %.4f  (@difficulty)' % world.xp_factor, C.SYSTEM)
            msg(client, channel,
                '  start_room:   %s' % start_label, C.SYSTEM)
            msg(client, channel,
                '  NPC templates: %d    Rooms: %d    Players ever: %d    '
                'Bans: %d    Quests: %d    Themes: %d' % (
                    n_npcs, n_rooms, n_players, n_bans, n_quests, n_themes),
                C.SYSTEM)
            if MUD_MODEL:
                try:
                    import ollama as _ollama_check  # noqa
                    ollama_status = 'available'
                except ImportError:
                    ollama_status = paint('NOT INSTALLED', bold=True)
                model_state = paint('on', bold=True) if wrow['model_enabled'] else 'off'
                tps_str = ('  %.1f tok/s' % _ollama_tps) if _ollama_tps else ''
                msg(client, channel,
                    '  MUD_MODEL:    %s  (ollama: %s)  enabled: %s%s    (@world model on|off)' % (
                        paint(MUD_MODEL, bold=True), ollama_status, model_state, tps_str),
                    C.SYSTEM)
            else:
                msg(client, channel,
                    '  MUD_MODEL:    DISABLED', C.SYSTEM)
            return

        if sub == 'model':
            if not MUD_MODEL:
                msg(client, channel,
                    '@world model: MUD_MODEL is not set in mud.py.', C.SYSTEM)
                return
            val = rest.strip().lower()
            if val not in ('on', 'off'):
                msg(client, channel,
                    'Usage: @world model on|off', C.SYSTEM)
                return
            if val == 'off':
                world.db.execute(
                    'UPDATE worlds SET model_enabled=0 WHERE world_name=?',
                    (world.world_name,)
                )
                world.db.commit()
                _release_ollama_client_if_unused(client.server)
                msg(client, channel,
                    'NPC AI model (%s) off.' % MUD_MODEL, C.SYSTEM)
            else:
                # Don't touch the DB yet — verify the model responds first.
                _ensure_ollama_client(client.server)
                msg(client, channel,
                    'Testing %s …' % paint(MUD_MODEL, bold=True), C.SYSTEM)
                asyncio.ensure_future(
                    _verify_and_enable_model(client, channel, world))
            return

        valid_fields = {'magic_name', 'magic_source', 'description'}
        if sub not in valid_fields:
            msg(client, channel,
                'Usage: @world  |  @world <magic_name|magic_source|description> <value>'
                '  |  @world model on|off',
                C.SYSTEM)
            return
        value = rest.strip()
        if not value:
            msg(client, channel, 'Usage: @world %s <value>' % sub, C.SYSTEM)
            return
        if sub == 'magic_source' and value not in ('levelup', 'item', 'vendor'):
            msg(client, channel,
                'magic_source must be: levelup  item  vendor', C.SYSTEM)
            return
        world.db.execute(
            'UPDATE worlds SET %s=? WHERE world_name=?' % sub,
            (value, world.world_name)
        )
        world.commit()
        msg(client, channel,
            'World %s set to %s.' % (sub, paint(value, bold=True)), C.SYSTEM)
        return

    # ── @reset ────────────────────────────────────────────────────────────
    if command == 'reset':
        if tier < 4:
            msg(client, channel, '@reset requires owner (~).', C.SYSTEM)
            return
        if sub != 'world':
            msg(client, channel,
                'Usage: @reset world  — wipes and re-seeds the entire world.',
                C.SYSTEM)
            return
        world_name = world.world_name
        for table in ('rooms', 'npcs', 'npc_instances', 'players', 'inventory',
                      'spells', 'guild_levels', 'status_effects', 'world_bans',
                      'quests', 'player_quests', 'autofight_profiles',
                      'themes', 'theme_fragments', 'theme_words',
                      'theme_npcs', 'theme_loot', 'theme_ambient'):
            world.db.execute(
                'DELETE FROM %s WHERE world=?' % table, (world_name,)
            )
        world.db.execute(
            'DELETE FROM worlds WHERE world_name=?', (world_name,)
        )
        world.db.commit()
        world._online.clear()
        world._follows.clear()
        world._tension.clear()
        world._spawn_cache.clear()
        world._defending.clear()
        world._lingering.clear()
        world._last_combat_action.clear()
        world._buffs.clear()
        _npc_combat.clear()
        _npc_brains.clear()
        _worlds.pop(world_name, None)
        task = _directors.pop(world_name, None)
        if task:
            task.cancel()
        for c in list(channel.clients):
            msg(c, channel,
                paint('The world has been reset.', bold=True), C.SYSTEM)
        new_world = _get_or_init_world(channel, client.server)
        if new_world is None:
            return
        try:
            loop = asyncio.get_event_loop()
            task = loop.create_task(
                _director(new_world, channel, client.server))
            _directors[world_name] = task
            if hasattr(client.server, 'mud_directors'):
                client.server.mud_directors[world_name] = task
        except RuntimeError:
            pass
        for c in list(channel.clients):
            _mud_join(c, channel, new_world)
        return

    # ── @difficulty ───────────────────────────────────────────────────────
    if command == 'difficulty':
        if tier < 4:
            msg(client, channel, '@difficulty requires owner (~).', C.SYSTEM)
            return

        # Load NPCs from this world that actually award XP, ordered ascending.
        npc_rows = world.db.execute(
            "SELECT name, JSON_EXTRACT(stats, '$.xp_value') AS xp_value "
            'FROM npcs WHERE world=? AND JSON_EXTRACT(stats, \'$.xp_value\') > 0 '
            'ORDER BY xp_value ASC',
            (world.world_name,)
        ).fetchall()

        if not npc_rows:
            msg(client, channel,
                'No NPCs with xp_value > 0 in this world.', C.SYSTEM)
            return

        diff_npcs  = [(r['name'], int(r['xp_value'])) for r in npc_rows]
        top_xp     = diff_npcs[-1][1]   # highest xp_value — bottom of table

        def _show_table(factor):
            total = _xp_threshold(31, factor)
            msg(client, channel,
                paint('Current difficulty  (factor=%.4f,  %d XP to reach lvl 32):' % (
                    factor, total), bold=True), C.SYSTEM)
            for name, xp in diff_npcs:
                kills = -(-total // xp)
                msg(client, channel,
                    '  %-22s %4d XP each  →  %d kills to lvl 32' % (
                        name, xp, kills), C.SYSTEM)
            return total

        if not sub:
            _show_table(world.xp_factor)
            msg(client, channel,
                'Set difficulty with: %s  (%s = %s, %d XP)' % (
                    paint('@difficulty <count>', bold=True),
                    paint('count', bold=True),
                    diff_npcs[-1][0], top_xp),
                C.SYSTEM)
            return

        try:
            target_count = int(sub)
            if target_count < 1:
                raise ValueError
        except ValueError:
            msg(client, channel,
                'Usage: @difficulty <count>  (positive integer)', C.SYSTEM)
            return

        target_xp = target_count * top_xp

        # Binary-search for the factor where threshold(31) <= target_xp.
        lo, hi = 1.0, 3.0
        for _ in range(200):
            mid = (lo + hi) / 2
            if _xp_threshold(31, mid) <= target_xp:
                lo = mid
            else:
                hi = mid
        new_factor = round((lo + hi) / 2, 4)

        world.db.execute(
            'UPDATE worlds SET xp_factor=? WHERE world_name=?',
            (new_factor, world.world_name)
        )
        world.db.commit()

        msg(client, channel,
            paint('Difficulty updated.', bold=True) +
            '  factor=%.4f' % new_factor, C.SYSTEM)
        _show_table(new_factor)
        return

    # ── @spawn ────────────────────────────────────────────────────────────
    if command == 'spawn':
        if sub == 'list':
            list_parts = rest.split() if rest else []
            kind       = list_parts[0].lower() if list_parts else ''
            if kind not in ('npcs', 'props'):
                msg(client, channel,
                    'Usage: @spawn list npcs|props [query] [--all]', C.SYSTEM)
                return
            all_worlds  = '--all' in list_parts
            query_parts = [p for p in list_parts[1:] if p != '--all']
            query       = ' '.join(query_parts).lower()

            if kind == 'npcs':
                if all_worlds:
                    sql    = ('SELECT world, npc_id, name, behavior, danger_tier '
                              'FROM npcs')
                    params = []
                    if query:
                        sql   += ' WHERE LOWER(name) LIKE ?'
                        params = ['%' + query + '%']
                    sql += ' ORDER BY world, name LIMIT 40'
                else:
                    sql    = ('SELECT world, npc_id, name, behavior, danger_tier '
                              'FROM npcs WHERE world=?')
                    params = [world.world_name]
                    if query:
                        sql   += ' AND LOWER(name) LIKE ?'
                        params.append('%' + query + '%')
                    sql += ' ORDER BY name LIMIT 40'
                rows = world.db.execute(sql, params).fetchall()
                if not rows:
                    msg(client, channel,
                        'No NPC templates found%s.' % (
                            ' matching "%s"' % query if query else ''),
                        C.SYSTEM)
                    return
                results = []
                msg(client, channel,
                    paint('NPC templates%s:' % (
                        ' (all worlds)' if all_worlds else ''), bold=True),
                    C.SYSTEM)
                for i, r in enumerate(rows):
                    prefix = ('[%s:%d] ' % (r['world'], r['npc_id'])
                              if all_worlds else '[%d] ' % r['npc_id'])
                    msg(client, channel,
                        '  %s%d. %s  tier:%d  %s' % (
                            prefix, i + 1, r['name'],
                            r['danger_tier'], r['behavior']), C.SYSTEM)
                    results.append((r['world'], 'npc', r['npc_id'], r['name']))
                world._spawn_cache[client.nick] = results
            else:
                if all_worlds:
                    sql    = ('SELECT world, item_id, name, item_type '
                              'FROM items')
                    params = []
                    if query:
                        sql   += ' WHERE LOWER(name) LIKE ?'
                        params = ['%' + query + '%']
                    sql += ' ORDER BY world, name LIMIT 40'
                else:
                    sql    = ('SELECT world, item_id, name, item_type '
                              'FROM items WHERE world=?')
                    params = [world.world_name]
                    if query:
                        sql   += ' AND LOWER(name) LIKE ?'
                        params.append('%' + query + '%')
                    sql += ' ORDER BY name LIMIT 40'
                rows = world.db.execute(sql, params).fetchall()
                if not rows:
                    msg(client, channel,
                        'No item templates found%s.' % (
                            ' matching "%s"' % query if query else ''),
                        C.SYSTEM)
                    return
                results = []
                msg(client, channel,
                    paint('Item templates%s:' % (
                        ' (all worlds)' if all_worlds else ''), bold=True),
                    C.SYSTEM)
                for i, r in enumerate(rows):
                    prefix = ('[%s:%d] ' % (r['world'], r['item_id'])
                              if all_worlds else '[%d] ' % r['item_id'])
                    msg(client, channel,
                        '  %s%d. %s  (%s)' % (
                            prefix, i + 1, r['name'], r['item_type']),
                        C.SYSTEM)
                    results.append((r['world'], 'prop', r['item_id'], r['name']))
                world._spawn_cache[client.nick] = results
            return

        if sub == 'npc':
            if tier < 2:
                msg(client, channel,
                    '@spawn npc requires op (@) or above.', C.SYSTEM)
                return
            target = rest.strip()
            if not target:
                msg(client, channel, 'Usage: @spawn npc <name|id>', C.SYSTEM)
                return
            if target.isdigit():
                nrow = world.db.execute(
                    'SELECT npc_id, name, stats FROM npcs '
                    'WHERE npc_id=? AND world=?',
                    (int(target), world.world_name)
                ).fetchone()
            else:
                nrow = world.db.execute(
                    'SELECT npc_id, name, stats FROM npcs '
                    'WHERE world=? AND LOWER(name) LIKE ? LIMIT 1',
                    (world.world_name, '%' + target.lower() + '%')
                ).fetchone()
            if not nrow:
                msg(client, channel,
                    'No NPC template matching "%s".' % target, C.SYSTEM)
                return
            max_b   = json.loads(nrow['stats'] or '{}').get('max_blood', 10)
            room_id = player['room_id']
            world.db.execute(
                'INSERT INTO npc_instances '
                '  (npc_id, world, room_id, spawn_room_id, current_blood, '
                '   state, next_action_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (nrow['npc_id'], world.world_name, room_id, room_id,
                 max_b, 'idle', time.time() + 2.0)
            )
            world.commit()
            msg(client, channel,
                'Spawned %s here.' % paint(nrow['name'], bold=True), C.SYSTEM)
            return

        if sub == 'prop':
            if tier < 2:
                msg(client, channel,
                    '@spawn prop requires op (@) or above.', C.SYSTEM)
                return
            target = rest.strip()
            if not target:
                msg(client, channel, 'Usage: @spawn prop <name|id>', C.SYSTEM)
                return
            if target.isdigit():
                irow = world.db.execute(
                    'SELECT item_id, name FROM items WHERE item_id=? AND world=?',
                    (int(target), world.world_name)
                ).fetchone()
            else:
                irow = world.db.execute(
                    'SELECT item_id, name FROM items '
                    'WHERE world=? AND LOWER(name) LIKE ? LIMIT 1',
                    (world.world_name, '%' + target.lower() + '%')
                ).fetchone()
            if not irow:
                msg(client, channel,
                    'No item template matching "%s".' % target, C.SYSTEM)
                return
            room = world.get_room(player['room_id'])
            if room is None:
                msg(client, channel, 'You are not in a valid room.', C.SYSTEM)
                return
            props = room.get('props', {})
            items = list(props.get('items', []))
            items.append({'name': irow['name'], 'item_id': irow['item_id']})
            props['items'] = items
            world.db.execute(
                'UPDATE rooms SET props=? WHERE room_id=? AND world=?',
                (json.dumps(props), room['room_id'], world.world_name)
            )
            world.commit()
            msg(client, channel,
                '%s placed in this room.' % paint(irow['name'], bold=True),
                C.SYSTEM)
            return

        if sub == 'copy':
            if tier < 3:
                msg(client, channel,
                    '@spawn copy requires admin (&) or owner (~).', C.SYSTEM)
                return
            parts2    = rest.split(None, 1)
            if len(parts2) < 2:
                msg(client, channel,
                    'Usage: @spawn copy npc|prop <world:id|n>', C.SYSTEM)
                return
            copy_kind = parts2[0].lower()
            ref       = parts2[1].strip()
            if copy_kind not in ('npc', 'prop'):
                msg(client, channel,
                    'Usage: @spawn copy npc|prop <ref>', C.SYSTEM)
                return
            # Resolve ref: result number or world:id
            src_world_name = None
            src_id         = None
            if ref.isdigit():
                cache = world._spawn_cache.get(client.nick, [])
                n = int(ref) - 1
                if n < 0 or n >= len(cache):
                    msg(client, channel,
                        'No result #%s — run @spawn list %ss first.' % (
                            ref, copy_kind), C.SYSTEM)
                    return
                src_world_name, _, src_id, _ = cache[n]
            elif ':' in ref:
                p3 = ref.rsplit(':', 1)
                if not p3[1].isdigit():
                    msg(client, channel,
                        'Invalid ref "%s". Format: <world>:<id>' % ref,
                        C.SYSTEM)
                    return
                src_world_name = p3[0]
                src_id         = int(p3[1])
            else:
                msg(client, channel,
                    'Invalid ref — use a result number or world:id.', C.SYSTEM)
                return
            if copy_kind == 'npc':
                src = world.db.execute(
                    'SELECT * FROM npcs WHERE npc_id=? AND world=?',
                    (src_id, src_world_name)
                ).fetchone()
                if not src:
                    msg(client, channel,
                        'NPC [%s:%d] not found.' % (src_world_name, src_id),
                        C.SYSTEM)
                    return
                cur = world.db.execute(
                    'INSERT INTO npcs '
                    '  (world, name, description, danger_tier, behavior, '
                    '   stats, loot, respawn_delay, dialogue) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (world.world_name,
                     src['name'], src['description'],
                     src['danger_tier'], src['behavior'],
                     src['stats'], src['loot'],
                     src['respawn_delay'], src['dialogue'])
                )
                world.commit()
                msg(client, channel,
                    'Copied %s from %s → new id %d.  '
                    'Use @spawn npc %d to place.' % (
                        paint(src['name'], bold=True), src_world_name,
                        cur.lastrowid, cur.lastrowid), C.SYSTEM)
            else:
                src = world.db.execute(
                    'SELECT * FROM items WHERE item_id=? AND world=?',
                    (src_id, src_world_name)
                ).fetchone()
                if not src:
                    msg(client, channel,
                        'Item [%s:%d] not found.' % (src_world_name, src_id),
                        C.SYSTEM)
                    return
                cur = world.db.execute(
                    'INSERT INTO items '
                    '  (world, name, description, item_type, stats, value) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (world.world_name,
                     src['name'], src['description'],
                     src['item_type'], src['stats'], src['value'])
                )
                world.commit()
                msg(client, channel,
                    'Copied %s from %s → new id %d.  '
                    'Use @spawn prop %d to place.' % (
                        paint(src['name'], bold=True), src_world_name,
                        cur.lastrowid, cur.lastrowid), C.SYSTEM)
            return

        msg(client, channel,
            'Usage: @spawn list npcs|props [query] [--all]  |  '
            '@spawn npc|prop <name|id>  |  '
            '@spawn copy npc|prop <world:id|n>', C.SYSTEM)
        return

    # ── @generate ─────────────────────────────────────────────────────────
    if command == 'generate':
        if sub == 'preview':
            parts2 = rest.split()
            if len(parts2) < 3:
                msg(client, channel,
                    'Usage: @generate preview <theme> <size> <difficulty> '
                    '[seed:N]', C.SYSTEM)
                return
            theme_n = parts2[0]
            size_n  = parts2[1].lower()
            diff_n  = parts2[2].lower()
            seed_v  = next(
                (int(p[5:]) for p in parts2[3:]
                 if p.startswith('seed:') and p[5:].isdigit()), None)
            _admin_generate(client, channel, world, player,
                            theme_n, size_n, diff_n, None, seed_v,
                            preview=True)
            return

        if sub in ('area', 'room'):
            if tier < 2:
                msg(client, channel,
                    '@generate requires op (@) or above.', C.SYSTEM)
                return
            if sub == 'area':
                parts2 = rest.split()
                if len(parts2) < 3:
                    msg(client, channel,
                        'Usage: @generate area <theme> <size> <difficulty> '
                        '[direction] [seed:N]', C.SYSTEM)
                    return
                theme_n = parts2[0]
                size_n  = parts2[1].lower()
                diff_n  = parts2[2].lower()
                attach  = None
                seed_v  = None
                for p in parts2[3:]:
                    if p.startswith('seed:') and p[5:].isdigit():
                        seed_v = int(p[5:])
                    elif _DIR_FULL.get(p, p) in _OPPOSITE:
                        attach = _DIR_FULL.get(p, p)
                _admin_generate(client, channel, world, player,
                                theme_n, size_n, diff_n, attach, seed_v)
            else:
                # @generate room <type> <theme>
                parts2 = rest.split()
                if len(parts2) < 2:
                    msg(client, channel,
                        'Usage: @generate room <type> <theme>', C.SYSTEM)
                    return
                theme_n = parts2[1]
                _admin_generate(client, channel, world, player,
                                theme_n, 'micro', 'medium', None, None)
            return

        msg(client, channel,
            'Usage: @generate area <theme> <size> <difficulty> [dir] [seed:N]  |  '
            '@generate room <type> <theme>  |  '
            '@generate preview <theme> <size> <difficulty>', C.SYSTEM)
        return

    # ── @theme ────────────────────────────────────────────────────────────
    if command == 'theme':
        if not sub:
            msg(client, channel,
                'Usage: @theme create <name>  |  '
                '@theme fragments/fragment/words/word/npc/loot/ambient ...',
                C.SYSTEM)
            return

        if sub == 'create':
            if tier < 3:
                msg(client, channel,
                    '@theme create requires admin (&) or owner (~).', C.SYSTEM)
                return
            theme_name = rest.strip().lower().replace(' ', '_')
            if not theme_name:
                msg(client, channel, 'Usage: @theme create <name>', C.SYSTEM)
                return
            if world.db.execute(
                'SELECT 1 FROM themes WHERE theme_name=? AND world=?',
                (theme_name, world.world_name)
            ).fetchone():
                msg(client, channel,
                    'Theme "%s" already exists.' % theme_name, C.SYSTEM)
                return
            world.db.execute(
                'INSERT INTO themes (theme_name, world, created_by) '
                'VALUES (?, ?, ?)',
                (theme_name, world.world_name, client.nick)
            )
            world.commit()
            msg(client, channel,
                'Theme %s created. Populate with @theme fragment/word/npc/loot/ambient.' % (
                    paint(theme_name, bold=True)), C.SYSTEM)
            return

        # All remaining subcommands take <theme_name> as next token.
        rest_parts = rest.split(None, 1) if rest else []
        theme_name = rest_parts[0].lower() if rest_parts else ''
        theme_rest = rest_parts[1] if len(rest_parts) > 1 else ''

        if sub in ('fragments', 'fragment'):
            tr      = theme_rest.split(None, 1) if theme_rest else []
            ftype   = tr[0].lower() if tr else ''
            frest   = tr[1] if len(tr) > 1 else ''
            vtypes  = {'atmosphere', 'structure', 'detail'}
            if ftype not in vtypes:
                msg(client, channel,
                    'Usage: @theme fragment(s) <theme> '
                    '<atmosphere|structure|detail> ...', C.SYSTEM)
                return

            if sub == 'fragments':
                rows = world.db.execute(
                    'SELECT id, text FROM theme_fragments '
                    'WHERE theme=? AND world=? AND frag_type=? ORDER BY id',
                    (theme_name, world.world_name, ftype)
                ).fetchall()
                if not rows:
                    msg(client, channel,
                        'No %s fragments for theme "%s".' % (
                            ftype, theme_name), C.SYSTEM)
                    return
                msg(client, channel,
                    paint('%s — %s:' % (theme_name, ftype), bold=True),
                    C.SYSTEM)
                for r in rows:
                    msg(client, channel, '  [%d] %s' % (r['id'], r['text']))
                return

            # @theme fragment — write/delete/test operations
            if frest == 'test':
                texts = [r['text'] for r in world.db.execute(
                    'SELECT text FROM theme_fragments '
                    'WHERE theme=? AND world=? AND frag_type=?',
                    (theme_name, world.world_name, ftype)
                ).fetchall()]
                if not texts:
                    msg(client, channel,
                        'No %s fragments for theme "%s".' % (
                            ftype, theme_name), C.SYSTEM)
                    return
                msg(client, channel,
                    paint('Sample %s fragments:' % ftype, bold=True), C.SYSTEM)
                for _ in range(min(3, len(texts))):
                    msg(client, channel, '  ' + random.choice(texts))
                return

            if tier < 3:
                msg(client, channel,
                    '@theme fragment editing requires admin (&) or owner (~).',
                    C.SYSTEM)
                return

            if frest.startswith(':'):
                text = frest[1:].strip()
                if not text:
                    msg(client, channel, 'Empty fragment text.', C.SYSTEM)
                    return
                world.db.execute(
                    'INSERT INTO theme_fragments '
                    '(theme, world, frag_type, text) VALUES (?, ?, ?, ?)',
                    (theme_name, world.world_name, ftype, text)
                )
                world.commit()
                msg(client, channel,
                    'Fragment added to %s/%s.' % (theme_name, ftype), C.SYSTEM)
                return

            fp = frest.split(None, 1) if frest else []
            if fp and fp[0] == 'del':
                n_str = fp[1].strip() if len(fp) > 1 else ''
                if not n_str.isdigit():
                    msg(client, channel,
                        'Usage: @theme fragment <theme> %s del <id>' % ftype,
                        C.SYSTEM)
                    return
                world.db.execute(
                    'DELETE FROM theme_fragments '
                    'WHERE id=? AND theme=? AND world=?',
                    (int(n_str), theme_name, world.world_name)
                )
                world.commit()
                msg(client, channel,
                    'Fragment %s deleted.' % n_str, C.SYSTEM)
                return

            if len(fp) >= 2 and fp[0].isdigit():
                new_text = fp[1].lstrip(':').strip()
                if not new_text:
                    msg(client, channel, 'Empty text.', C.SYSTEM)
                    return
                world.db.execute(
                    'UPDATE theme_fragments SET text=? '
                    'WHERE id=? AND theme=? AND world=?',
                    (new_text, int(fp[0]), theme_name, world.world_name)
                )
                world.commit()
                msg(client, channel,
                    'Fragment %s updated.' % fp[0], C.SYSTEM)
                return

            msg(client, channel,
                'Usage: @theme fragment <theme> <type> :<text>  '
                '|  <n> :<text>  |  del <n>  |  test', C.SYSTEM)
            return

        if sub in ('words', 'word'):
            tr     = theme_rest.split(None, 1) if theme_rest else []
            wtype  = tr[0].lower() if tr else ''
            wrest  = tr[1] if len(tr) > 1 else ''
            if wtype not in ('adjective', 'noun'):
                msg(client, channel,
                    'Usage: @theme word(s) <theme> <adjective|noun> ...', C.SYSTEM)
                return

            if sub == 'words':
                rows = world.db.execute(
                    'SELECT id, text FROM theme_words '
                    'WHERE theme=? AND world=? AND word_type=? ORDER BY id',
                    (theme_name, world.world_name, wtype)
                ).fetchall()
                if not rows:
                    msg(client, channel,
                        'No %s words for theme "%s".' % (wtype, theme_name),
                        C.SYSTEM)
                    return
                msg(client, channel,
                    paint('%s — %s words:' % (theme_name, wtype), bold=True),
                    C.SYSTEM)
                for r in rows:
                    msg(client, channel, '  [%d] %s' % (r['id'], r['text']))
                return

            if tier < 3:
                msg(client, channel,
                    '@theme word editing requires admin (&) or owner (~).',
                    C.SYSTEM)
                return

            wp = wrest.split(None, 1) if wrest else []
            if wrest.startswith(':'):
                text = wrest[1:].strip()
                if not text:
                    msg(client, channel, 'Empty word text.', C.SYSTEM)
                    return
                world.db.execute(
                    'INSERT INTO theme_words (theme, world, word_type, text) '
                    'VALUES (?, ?, ?, ?)',
                    (theme_name, world.world_name, wtype, text)
                )
                world.commit()
                msg(client, channel,
                    '%s word "%s" added to %s.' % (wtype, text, theme_name),
                    C.SYSTEM)
                return

            if wp and wp[0] == 'del':
                n_str = wp[1].strip() if len(wp) > 1 else ''
                if not n_str.isdigit():
                    msg(client, channel,
                        'Usage: @theme word <theme> %s del <id>' % wtype,
                        C.SYSTEM)
                    return
                world.db.execute(
                    'DELETE FROM theme_words WHERE id=? AND theme=? AND world=?',
                    (int(n_str), theme_name, world.world_name)
                )
                world.commit()
                msg(client, channel, 'Word %s deleted.' % n_str, C.SYSTEM)
                return

            msg(client, channel,
                'Usage: @theme word <theme> <adjective|noun> :<text>  '
                '|  del <id>', C.SYSTEM)
            return

        if sub == 'npc':
            if tier < 3:
                msg(client, channel,
                    '@theme npc requires admin (&) or owner (~).', C.SYSTEM)
                return
            tp = theme_rest.split(None, 1) if theme_rest else []
            ta = tp[0] if tp else ''
            tr = tp[1] if len(tp) > 1 else ''

            if ta == 'del':
                if not tr.strip().isdigit():
                    msg(client, channel,
                        'Usage: @theme npc <theme> del <id>', C.SYSTEM)
                    return
                world.db.execute(
                    'DELETE FROM theme_npcs WHERE id=? AND theme=? AND world=?',
                    (int(tr.strip()), theme_name, world.world_name)
                )
                world.commit()
                msg(client, channel, 'Theme NPC %s removed.' % tr.strip(), C.SYSTEM)
                return

            if ta.startswith('tier:') and tr.startswith(':'):
                tier_str = ta[5:]
                if not tier_str.isdigit():
                    msg(client, channel,
                        'Usage: @theme npc <theme> tier:<0-4> :<npc_name>',
                        C.SYSTEM)
                    return
                npc_name = tr[1:].strip()
                if not npc_name:
                    msg(client, channel, 'Empty NPC name.', C.SYSTEM)
                    return
                world.db.execute(
                    'INSERT INTO theme_npcs '
                    '(theme, world, npc_name, danger_tier) VALUES (?, ?, ?, ?)',
                    (theme_name, world.world_name, npc_name, int(tier_str))
                )
                world.commit()
                msg(client, channel,
                    'Added %s (tier %s) to theme %s.' % (
                        npc_name, tier_str, theme_name), C.SYSTEM)
                return

            rows = world.db.execute(
                'SELECT id, npc_name, danger_tier FROM theme_npcs '
                'WHERE theme=? AND world=? ORDER BY danger_tier, npc_name',
                (theme_name, world.world_name)
            ).fetchall()
            if not rows:
                msg(client, channel,
                    'No NPCs in theme "%s".' % theme_name, C.SYSTEM)
                return
            msg(client, channel,
                paint('NPCs in theme %s:' % theme_name, bold=True), C.SYSTEM)
            for r in rows:
                msg(client, channel,
                    '  [%d] tier%d  %s' % (
                        r['id'], r['danger_tier'], r['npc_name']), C.SYSTEM)
            return

        if sub == 'loot':
            if tier < 3:
                msg(client, channel,
                    '@theme loot requires admin (&) or owner (~).', C.SYSTEM)
                return
            tp = theme_rest.split(None, 1) if theme_rest else []
            ta = tp[0] if tp else ''
            tr = tp[1] if len(tp) > 1 else ''

            if ta == 'del':
                if not tr.strip().isdigit():
                    msg(client, channel,
                        'Usage: @theme loot <theme> del <id>', C.SYSTEM)
                    return
                world.db.execute(
                    'DELETE FROM theme_loot WHERE id=? AND theme=? AND world=?',
                    (int(tr.strip()), theme_name, world.world_name)
                )
                world.commit()
                msg(client, channel, 'Loot %s removed.' % tr.strip(), C.SYSTEM)
                return

            if ta.startswith(':'):
                # @theme loot <theme> :<item_name> weight:<n>
                full = (ta[1:] + (' ' + tr if tr else '')).strip()
                weight_val = 10
                item_name  = full
                for tok in full.split():
                    if tok.startswith('weight:') and tok[7:].isdigit():
                        weight_val = int(tok[7:])
                        item_name  = full.replace(tok, '').strip()
                        break
                if not item_name:
                    msg(client, channel, 'Empty item name.', C.SYSTEM)
                    return
                world.db.execute(
                    'INSERT INTO theme_loot (theme, world, item_name, weight) '
                    'VALUES (?, ?, ?, ?)',
                    (theme_name, world.world_name, item_name, weight_val)
                )
                world.commit()
                msg(client, channel,
                    'Added "%s" weight:%d to theme %s.' % (
                        item_name, weight_val, theme_name), C.SYSTEM)
                return

            rows = world.db.execute(
                'SELECT id, item_name, weight FROM theme_loot '
                'WHERE theme=? AND world=? ORDER BY weight DESC',
                (theme_name, world.world_name)
            ).fetchall()
            if not rows:
                msg(client, channel,
                    'No loot in theme "%s".' % theme_name, C.SYSTEM)
                return
            msg(client, channel,
                paint('Loot in theme %s:' % theme_name, bold=True), C.SYSTEM)
            for r in rows:
                msg(client, channel,
                    '  [%d] %s  weight:%d' % (
                        r['id'], r['item_name'], r['weight']), C.SYSTEM)
            return

        if sub == 'ambient':
            if tier < 3:
                msg(client, channel,
                    '@theme ambient requires admin (&) or owner (~).', C.SYSTEM)
                return
            tp = theme_rest.split(None, 1) if theme_rest else []
            ta = tp[0] if tp else ''
            tr = tp[1] if len(tp) > 1 else ''

            if ta == 'del':
                if not tr.strip().isdigit():
                    msg(client, channel,
                        'Usage: @theme ambient <theme> del <id>', C.SYSTEM)
                    return
                world.db.execute(
                    'DELETE FROM theme_ambient '
                    'WHERE id=? AND theme=? AND world=?',
                    (int(tr.strip()), theme_name, world.world_name)
                )
                world.commit()
                msg(client, channel,
                    'Ambient %s removed.' % tr.strip(), C.SYSTEM)
                return

            if ta.startswith(':'):
                text = (ta[1:] + (' ' + tr if tr else '')).strip()
                if not text:
                    msg(client, channel, 'Empty ambient text.', C.SYSTEM)
                    return
                world.db.execute(
                    'INSERT INTO theme_ambient (theme, world, text) '
                    'VALUES (?, ?, ?)',
                    (theme_name, world.world_name, text)
                )
                world.commit()
                msg(client, channel,
                    'Ambient string added to theme %s.' % theme_name, C.SYSTEM)
                return

            rows = world.db.execute(
                'SELECT id, text FROM theme_ambient '
                'WHERE theme=? AND world=? ORDER BY id',
                (theme_name, world.world_name)
            ).fetchall()
            if not rows:
                msg(client, channel,
                    'No ambient strings in theme "%s".' % theme_name, C.SYSTEM)
                return
            msg(client, channel,
                paint('Ambient strings in %s:' % theme_name, bold=True),
                C.SYSTEM)
            for r in rows:
                msg(client, channel, '  [%d] %s' % (r['id'], r['text']))
            return

        msg(client, channel,
            'Usage: @theme create <name>  |  '
            '@theme fragments/fragment <theme> <type> [...]  |  '
            '@theme words/word <theme> <type> [...]  |  '
            '@theme npc/loot/ambient <theme> [...]', C.SYSTEM)
        return

    # ── @list ─────────────────────────────────────────────────────────────
    if command == 'list':
        # @list rooms / @list npcs / @list items / @list bans
        # @list players [all] / @list themes / @list quests
        what = sub.lower() if sub else ''
        if what in ('rooms', 'room'):
            _cmd_admin(client, channel, world, player, 'rooms', '')
            return
        if what in ('npcs', 'npc'):
            _cmd_admin(client, channel, world, player, 'spawn', 'list npcs ' + rest)
            return
        if what in ('items', 'item', 'props', 'prop'):
            _cmd_admin(client, channel, world, player, 'spawn', 'list props ' + rest)
            return
        if what in ('bans', 'ban'):
            _cmd_admin(client, channel, world, player, 'ban', 'list')
            return
        if what == 'players':
            sub2 = rest.strip().lower()
            _cmd_admin(client, channel, world, player, 'who',
                       'all' if sub2 == 'all' else '')
            return
        if what in ('themes', 'theme'):
            rows = world.db.execute(
                'SELECT name FROM themes WHERE world=? ORDER BY name',
                (world.world_name,)
            ).fetchall()
            if not rows:
                msg(client, channel, 'No themes in this world.', C.SYSTEM)
                return
            msg(client, channel, paint('Themes:', bold=True), C.SYSTEM)
            for r in rows:
                msg(client, channel, '  ' + r['name'], C.SYSTEM)
            return
        if what in ('quests', 'quest'):
            rows = world.db.execute(
                'SELECT quest_id, title FROM quests WHERE world=? ORDER BY title',
                (world.world_name,)
            ).fetchall()
            if not rows:
                msg(client, channel, 'No quests in this world.', C.SYSTEM)
                return
            msg(client, channel, paint('Quests:', bold=True), C.SYSTEM)
            for r in rows:
                msg(client, channel, '  [%s] %s' % (r['quest_id'], r['title']), C.SYSTEM)
            return
        msg(client, channel,
            'Usage: @list rooms|npcs|items|bans|players [all]|themes|quests',
            C.SYSTEM)
        return

    # ── @create ───────────────────────────────────────────────────────────
    if command == 'create':
        what_sub = sub.lower() if sub else ''
        if what_sub == 'room':
            if tier < 2:
                msg(client, channel, '@create room requires op (@) or above.', C.SYSTEM)
                return
            # @create room <dir> [name]
            create_parts = rest.split(None, 1) if rest else []
            if not create_parts:
                msg(client, channel,
                    'Usage: @create room <direction> [room name]', C.SYSTEM)
                return
            raw_dir = create_parts[0].lower()
            new_dir = _DIR_FULL.get(raw_dir, raw_dir)
            if new_dir not in _OPPOSITE:
                msg(client, channel,
                    'Invalid direction. Use: north south east west up down',
                    C.SYSTEM)
                return
            cur_room = world.get_room(player['room_id'])
            if cur_room is None:
                msg(client, channel, 'You are not in a valid room.', C.SYSTEM)
                return
            if new_dir in cur_room.get('exits', {}):
                msg(client, channel,
                    'There is already an exit to the %s.' % new_dir, C.SYSTEM)
                return
            new_name = create_parts[1].strip() if len(create_parts) > 1 else 'New Room'
            new_rid = world.db.execute(
                'INSERT INTO rooms (world, name, description, exits, props, is_safe) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (world.world_name, new_name, '', '{}', '{}', 0)
            ).lastrowid
            # Bidirectional exits — read-modify-write to match existing pattern.
            back_dir = _OPPOSITE[new_dir]
            cur_exits = dict(cur_room.get('exits', {}))
            cur_exits[new_dir] = new_rid
            world.db.execute(
                'UPDATE rooms SET exits=? WHERE room_id=? AND world=?',
                (json.dumps(cur_exits), player['room_id'], world.world_name)
            )
            new_room_exits = {back_dir: player['room_id']}
            world.db.execute(
                'UPDATE rooms SET exits=? WHERE room_id=? AND world=?',
                (json.dumps(new_room_exits), new_rid, world.world_name)
            )
            world.update_player(client.nick, room_id=new_rid)
            world.commit()
            msg(client, channel,
                paint('Created: ', bold=True) +
                paint(new_name, bold=True) +
                ' [room_id: %d] to the %s. '
                'You are now there. Use @modify room desc <text> to describe it.' % (
                    new_rid, new_dir), C.SYSTEM)
            _show_room(client, channel, world, new_rid)
            return

        if what_sub == 'npc':
            if tier < 3:
                msg(client, channel,
                    '@create npc requires admin (&) or above.', C.SYSTEM)
                return
            # Delegate to @npc add
            _cmd_admin(client, channel, world, player, 'npc', 'add ' + rest)
            return

        if what_sub == 'theme':
            if tier < 3:
                msg(client, channel,
                    '@create theme requires admin (&) or above.', C.SYSTEM)
                return
            # Delegate to @theme create
            _cmd_admin(client, channel, world, player, 'theme', 'create ' + rest)
            return

        msg(client, channel,
            'Usage: @create room <dir> [name]  |  @create npc <name>  |  '
            '@create theme <name>', C.SYSTEM)
        return

    # ── @attach ───────────────────────────────────────────────────────────
    if command == 'attach':
        if tier < 2:
            msg(client, channel, '@attach requires op (@) or above.', C.SYSTEM)
            return
        # @attach <room_id> <direction> [--oneway]
        a_parts = args.split() if args else []
        if len(a_parts) < 2:
            msg(client, channel,
                'Usage: @attach <room_id> <direction> [--oneway]', C.SYSTEM)
            return
        try:
            target_rid = int(a_parts[0])
        except ValueError:
            msg(client, channel, 'room_id must be an integer.', C.SYSTEM)
            return
        raw_dir  = a_parts[1].lower()
        new_dir  = _DIR_FULL.get(raw_dir, raw_dir)
        if new_dir not in _OPPOSITE:
            msg(client, channel,
                'Invalid direction. Use: north south east west up down', C.SYSTEM)
            return
        oneway = '--oneway' in a_parts
        target_rm = world.get_room(target_rid)
        if target_rm is None:
            msg(client, channel,
                'No room with id %d in this world.' % target_rid, C.SYSTEM)
            return
        cur_room = world.get_room(player['room_id'])
        if cur_room is None:
            msg(client, channel, 'You are not in a valid room.', C.SYSTEM)
            return
        # Read-modify-write exits to match existing pattern.
        cur_exits = dict(cur_room.get('exits', {}))
        cur_exits[new_dir] = target_rid
        world.db.execute(
            'UPDATE rooms SET exits=? WHERE room_id=? AND world=?',
            (json.dumps(cur_exits), player['room_id'], world.world_name)
        )
        if not oneway:
            back_dir = _OPPOSITE[new_dir]
            tgt_exits = dict(target_rm.get('exits', {}))
            tgt_exits[back_dir] = player['room_id']
            world.db.execute(
                'UPDATE rooms SET exits=? WHERE room_id=? AND world=?',
                (json.dumps(tgt_exits), target_rid, world.world_name)
            )
        world.commit()
        direction_label = ('%s (one-way)' % new_dir) if oneway else (
            '%s ↔ %s' % (new_dir, _OPPOSITE[new_dir]))
        msg(client, channel,
            paint('Attached:', bold=True) +
            ' [%d] %s  %s  [%d] %s' % (
                player['room_id'], cur_room.get('name', '?'),
                direction_label,
                target_rid, target_rm.get('name', '?')), C.SYSTEM)
        return

    # ── @modify ───────────────────────────────────────────────────────────
    if command == 'modify':
        if tier < 2:
            msg(client, channel, '@modify requires op (@) or above.', C.SYSTEM)
            return
        what_m = sub.lower() if sub else ''
        if what_m in ('room', ''):
            # @modify room <sub2> <args> — defaults to current room
            _cmd_admin(client, channel, world, player, 'room',
                       rest if rest else sub)
            return
        if what_m == 'npc':
            if tier < 3:
                msg(client, channel,
                    '@modify npc requires admin (&) or above.', C.SYSTEM)
                return
            _cmd_admin(client, channel, world, player, 'npc', rest)
            return
        if what_m == 'player':
            if tier < 3:
                msg(client, channel,
                    '@modify player requires admin (&) or above.', C.SYSTEM)
                return
            _cmd_admin(client, channel, world, player, 'player', rest)
            return
        if what_m in ('world', 'settings'):
            if tier < 3:
                msg(client, channel,
                    '@modify world requires admin (&) or above.', C.SYSTEM)
                return
            _cmd_admin(client, channel, world, player, 'world', rest)
            return
        msg(client, channel,
            'Usage: @modify room <desc|name|exit|safe> [...]  |  '
            '@modify npc <...>  |  @modify player <...>  |  @modify world <...>',
            C.SYSTEM)
        return

    msg(client, channel,
        paint('@%s' % command, bold=True) +
        ' — unknown admin command. '
        'Type %s for a list.' % paint('help @commands', bold=True), C.SYSTEM)


# ---------------------------------------------------------------------------
# Combat helpers
# ---------------------------------------------------------------------------

_GUILD_FAMILIES = {
    'Warrior':   'warrior', 'Mercenary':  'warrior',
    'Mage':      'mage',    'Netrunner':  'mage',
    'Rogue':     'rogue',   'Ghost':      'rogue',
    'Cleric':    'cleric',  'Ripperdoc':  'cleric',
}
_GUILD_BLOOD_FACTOR   = {'warrior': 1.5, 'mage': 0.8, 'rogue': 1.0, 'cleric': 1.1}
_GUILD_STAMINA_FACTOR = {'warrior': 0.8, 'mage': 1.5, 'rogue': 1.2, 'cleric': 1.1}
_XP_FACTOR = 1.0186

# Spell name → (canonical_effect, stamina_cost)
_SPELL_CANON = {
    'heal':             ('heal',          5),
    'patch up':         ('heal',          5),
    'magic missile':    ('magic_missile', 4),
    'hack':             ('magic_missile', 4),
    'fireball':         ('fireball',     10),
    'system crash':     ('fireball',     10),
    'ice storm':        ('ice_storm',    12),
    'ice breaker':      ('ice_storm',    12),
    'teleport':         ('teleport',     15),
    'jack in':          ('teleport',     15),
    'bless':            ('bless',         8),
    'overclock':        ('bless',         8),
    'smite':            ('smite',         6),
    'shock':            ('smite',         6),
    'taunt':            ('taunt',         3),
    'provoke':          ('taunt',         3),
    'shield bash':      ('shield_bash',   5),
    'flash bang':       ('shield_bash',   5),
    'berserk':          ('berserk',       8),
    'combat stims':     ('berserk',       8),
    'whirlwind':        ('whirlwind',    12),
    'suppressive fire': ('whirlwind',    12),
    'stealth':          ('stealth',       2),
    'ghost protocol':   ('stealth',       2),
    'backstab':         ('backstab',      8),
    'execution':        ('backstab',      8),
    # New canonical effects
    'chain lightning':  ('chain_lightning', 8),
    'arc discharge':    ('chain_lightning', 8),
    'drain':            ('drain',           6),
    'data siphon':      ('drain',           6),
    'detect':           ('detect',          2),
    'analyze':          ('detect',          2),
    'mend':             ('mend',            6),
    'nano-heal':        ('mend',            6),
    'curse':            ('curse',           5),
    'system virus':     ('curse',           5),
    'blind':            ('blind',           4),
    'sensor jam':       ('blind',           4),
    'leech':            ('leech',           7),
    'power drain':      ('leech',           7),
    'rally':            ('rally',          10),
    'broadcast boost':  ('rally',          10),
    'poison blade':     ('poison_blade',    4),
    'nano-toxin':       ('poison_blade',    4),
    'stone skin':       ('stone_skin',      9),
    'hardened chassis': ('stone_skin',      9),
    # ── Tier-2 spells (levels 13-21) ─────────────────────────────────────────
    'bind':             ('bind',            5),
    'root access':      ('bind',            5),
    'shatter':          ('shatter',         7),
    'deconstruct':      ('shatter',         7),
    'blood pact':       ('blood_pact',      4),
    'risk protocol':    ('blood_pact',      4),
    'ward':             ('ward',            6),
    'firewall':         ('ward',            6),
    'time stop':        ('time_stop',      14),
    'system freeze':    ('time_stop',      14),
    'meteor':           ('meteor',         18),
    'data nuke':        ('meteor',         18),
    'absorb':           ('absorb',          6),
    'data harvest':     ('absorb',          6),
    'consecrate':       ('consecrate',     12),
    'overwrite':        ('consecrate',     12),
    'spirit link':      ('spirit_link',    10),
    'sync link':        ('spirit_link',    10),
    'shockwave':        ('shockwave',       8),
    'emp burst':        ('shockwave',       8),
    # ── Tier-3 spells (levels 23-31) ─────────────────────────────────────────
    'apocalypse':       ('apocalypse',     20),
    'zero day':         ('apocalypse',     20),
    'time warp':        ('time_warp',      15),
    'clock spike':      ('time_warp',      15),
    'soul steal':       ('soul_steal',     10),
    'identity theft':   ('soul_steal',     10),
    'void walk':        ('void_walk',      16),
    'dark net':         ('void_walk',      16),
    'maelstrom':        ('maelstrom',      14),
    'feedback loop':    ('maelstrom',      14),
    'divine intervention': ('divine_intervention', 25),
    'emergency override':  ('divine_intervention', 25),
    'mind control':     ('mind_control',   15),
    'puppet master':    ('mind_control',   15),
    'necromancy':       ('necromancy',     18),
    'reboot':           ('necromancy',     18),
    'singularity':      ('singularity',    22),
    'kernel panic':     ('singularity',    22),
    'apotheosis':       ('apotheosis',     20),
    'godmode':          ('apotheosis',     20),
}

# Guild → [(min_player_level, spell_name), …]
# Spells are awarded automatically on reaching the required level.
_GUILD_SPELL_PROGRESSION = {
    'Warrior':   [(2,'shield bash'),    (4,'berserk'),        (6,'whirlwind'),
                  (8,'taunt'),          (10,'leech'),         (12,'blind'),
                  (14,'bind'),          (16,'shatter'),       (18,'blood pact'),
                  (20,'ward'),          (22,'time stop'),
                  (24,'shockwave'),     (26,'maelstrom'),     (28,'void walk'),
                  (30,'apotheosis'),    (32,'apocalypse')],
    'Mage':      [(2,'magic missile'),  (4,'fireball'),       (6,'chain lightning'),
                  (8,'ice storm'),      (10,'drain'),         (12,'detect'),
                  (14,'meteor'),        (16,'time stop'),     (18,'absorb'),
                  (20,'consecrate'),    (22,'bind'),
                  (24,'apocalypse'),    (26,'singularity'),   (28,'void walk'),
                  (30,'apotheosis'),    (32,'time warp')],
    'Rogue':     [(2,'stealth'),        (4,'backstab'),       (6,'pickpocket'),
                  (8,'poison blade'),   (10,'leech'),         (12,'evasion'),
                  (14,'shatter'),       (16,'absorb'),        (18,'bind'),
                  (20,'blood pact'),    (22,'ward'),
                  (24,'shockwave'),     (26,'void walk'),     (28,'mind control'),
                  (30,'maelstrom'),     (32,'apotheosis')],
    'Cleric':    [(2,'heal'),           (4,'bless'),          (6,'mend'),
                  (8,'smite'),          (10,'resurrect'),     (12,'rally'),
                  (14,'ward'),          (16,'consecrate'),    (18,'spirit link'),
                  (20,'bind'),          (22,'time stop'),
                  (24,'divine intervention'), (26,'necromancy'), (28,'soul steal'),
                  (30,'apotheosis'),    (32,'void walk')],
    'Mercenary': [(2,'flash bang'),     (4,'combat stims'),   (6,'suppressive fire'),
                  (8,'provoke'),        (10,'power drain'),   (12,'sensor jam'),
                  (14,'root access'),   (16,'deconstruct'),   (18,'risk protocol'),
                  (20,'firewall'),      (22,'system freeze'),
                  (24,'emp burst'),     (26,'feedback loop'), (28,'dark net'),
                  (30,'godmode'),       (32,'zero day')],
    'Netrunner': [(2,'hack'),           (4,'system crash'),   (6,'arc discharge'),
                  (8,'ice breaker'),    (10,'data siphon'),   (12,'analyze'),
                  (14,'data nuke'),     (16,'system freeze'), (18,'data harvest'),
                  (20,'overwrite'),     (22,'root access'),
                  (24,'zero day'),      (26,'kernel panic'),  (28,'dark net'),
                  (30,'godmode'),       (32,'clock spike')],
    'Ghost':     [(2,'ghost protocol'), (4,'execution'),      (6,'pickpocket'),
                  (8,'nano-toxin'),     (10,'power drain'),   (12,'evasion'),
                  (14,'deconstruct'),   (16,'data harvest'),  (18,'root access'),
                  (20,'risk protocol'), (22,'firewall'),
                  (24,'emp burst'),     (26,'dark net'),      (28,'puppet master'),
                  (30,'feedback loop'), (32,'godmode')],
    'Ripperdoc': [(2,'patch up'),       (4,'overclock'),      (6,'nano-heal'),
                  (8,'shock'),          (10,'resurrect'),     (12,'broadcast boost'),
                  (14,'firewall'),      (16,'overwrite'),     (18,'sync link'),
                  (20,'root access'),   (22,'system freeze'),
                  (24,'emergency override'), (26,'reboot'),   (28,'clock spike'),
                  (30,'godmode'),       (32,'dark net')],
}


def _xp_threshold(level, factor=None):
    """Total cumulative XP needed to advance past the given level."""
    f = factor if factor is not None else _XP_FACTOR
    return sum(int(10 * (f ** k)) for k in range(level))


def _guild_level_for(world, nick, guild):
    """Return guild_level integer for nick in guild, or 0."""
    row = world.db.execute(
        'SELECT guild_level FROM guild_levels WHERE nick=? AND world=? AND guild=?',
        (nick, world.world_name, guild)
    ).fetchone()
    return int(row['guild_level']) if row else 0


def _equipped_weapon(world, nick):
    """Return (damage, name) of nick's equipped weapon, or (0, None)."""
    row = world.db.execute(
        'SELECT i.name, i.stats '
        'FROM inventory inv JOIN items i ON inv.item_id = i.item_id '
        'WHERE inv.nick=? AND inv.world=? AND inv.equipped=1 '
        '  AND i.item_type="weapon" AND inv.on_corpse=0',
        (nick, world.world_name)
    ).fetchone()
    if not row:
        return 0, None
    return json.loads(row['stats'] or '{}').get('damage', 0), row['name']


def _equipped_armor(world, nick):
    """Return (defense, name) of nick's equipped armor, or (0, None)."""
    row = world.db.execute(
        'SELECT i.name, i.stats '
        'FROM inventory inv JOIN items i ON inv.item_id = i.item_id '
        'WHERE inv.nick=? AND inv.world=? AND inv.equipped=1 '
        '  AND i.item_type="armor" AND inv.on_corpse=0',
        (nick, world.world_name)
    ).fetchone()
    if not row:
        return 0, None
    return json.loads(row['stats'] or '{}').get('defense', 0), row['name']


def _player_defense(world, nick):
    """
    Return total incoming-damage reduction for nick (armor + active buff).
    A 'ward' flag on the buff dict is consumed on first call — it absorbs one
    hit completely, then clears itself.
    """
    armor_def = _equipped_armor(world, nick)[0]
    buff      = world._buffs.get(nick, {})
    if not buff or buff.get('expires_at', 0) <= time.time():
        return armor_def
    # Ward: absorb one hit entirely, then remove.
    if buff.get('ward'):
        buff['ward'] = False
        return armor_def + 999
    return armor_def + buff.get('defense', 0)


def _award_guild_spells(world, channel, client, nick, guild, old_level, new_level):
    """
    Insert any spells earned between old_level (exclusive) and new_level
    (inclusive) according to _GUILD_SPELL_PROGRESSION.  Notifies the player.
    """
    progression = _GUILD_SPELL_PROGRESSION.get(guild, [])
    for req_level, spell_name in progression:
        if old_level < req_level <= new_level:
            exists = world.db.execute(
                'SELECT 1 FROM spells WHERE nick=? AND world=? AND spell_name=?',
                (nick, world.world_name, spell_name)
            ).fetchone()
            if not exists:
                world.db.execute(
                    'INSERT INTO spells (nick, world, spell_name) VALUES (?, ?, ?)',
                    (nick, world.world_name, spell_name)
                )
                if client:
                    magic = world.get_world().get('magic_name') or 'spells'
                    msg(client, channel,
                        paint('New %s unlocked: ' % magic.rstrip('s'), bold=True,
                              color=C.SPELL) +
                        paint(spell_name, color=C.SPELL), C.SPELL)


def _apply_xp(world, channel, client, player, xp_gain):
    """
    Add xp_gain to player.xp and apply level-ups (cascading).
    Sends XP and level-up messages.  Returns updated player dict.
    """
    nick   = client.nick
    new_xp = player['xp'] + xp_gain
    world.update_player(nick, xp=new_xp)
    player = world.get_player(nick)

    msg(client, channel,
        paint('+%d XP' % xp_gain, color=C.XP) +
        ' (%d total)' % new_xp, C.XP)

    while new_xp >= _xp_threshold(player['level'], world.xp_factor):
        old_level = player['level']
        level     = old_level + 1
        guild     = player.get('guild')
        family    = _GUILD_FAMILIES.get(guild, 'warrior')
        bg        = int(5 * level * _GUILD_BLOOD_FACTOR.get(family, 1.0))
        sg        = int(3 * level * _GUILD_STAMINA_FACTOR.get(family, 1.0))
        new_mb    = player['max_blood']   + bg
        new_ms    = player['max_stamina'] + sg
        world.update_player(nick, level=level,
                            max_blood=new_mb, blood=new_mb,
                            max_stamina=new_ms)
        if guild:
            world.db.execute(
                'UPDATE guild_levels SET guild_level = guild_level + 1 '
                'WHERE nick=? AND world=? AND guild=?',
                (nick, world.world_name, guild))
        msg(client, channel,
            paint('Level up!', bold=True, color=C.LEVELUP) +
            ' You are now level %d.  '
            'Blood: %d (+%d)  Stamina: %d (+%d)' % (
                level, new_mb, bg, new_ms, sg), C.LEVELUP)
        if guild:
            _award_guild_spells(world, channel, client, nick, guild,
                                old_level, level)
        player = world.get_player(nick)
    return player


def _accrue_karma(world, nick, delta):
    """
    Add delta to nick's karma in-place. Clamps to [-100, 100].
    Positive actions: moving/looking/talking (+0.001), attacking hostile (+0.002),
    killing hostile (+0.01), healing party (+0.05), completing quest (+0.1).
    Negative actions: hurting friendly/party NPC (-0.05).
    Does not commit — caller must call world.commit() when ready.
    """
    p = world.get_player(nick)
    if p is None:
        return
    current = float(p.get('karma', 0.0) or 0.0)
    new_karma = max(-100.0, min(100.0, current + delta))
    world.update_player(nick, karma=new_karma)


def _mark_player_corpse(world, nick):
    """
    Mark all non-equipped inventory items as on_corpse=1.
    Returns a list of item_ids that were marked.
    """
    rows = world.db.execute(
        'SELECT rowid, item_id FROM inventory '
        'WHERE nick=? AND world=? AND equipped=0 AND on_corpse=0',
        (nick, world.world_name)
    ).fetchall()
    if not rows:
        return []
    item_ids = [r['item_id'] for r in rows]
    world.db.execute(
        'UPDATE inventory SET on_corpse=1 '
        'WHERE nick=? AND world=? AND equipped=0 AND on_corpse=0',
        (nick, world.world_name)
    )
    return item_ids


def _do_autoloot(world, channel, room_id, item_ids, source_label, corpse_nick=None):
    """
    Autoloot sampler.  Gather all willing looters in room_id:
      • Players with autoloot enabled in their autofight profile.
      • Non-passive NPC instances present in the room.
    Scale each actor's level to a ProbDist summing to 100, pick a winner,
    then resolve the transfer and broadcast the result to the room.

    item_ids  — list of item_id ints to resolve names for messaging.
    corpse_nick — if set, items are already in inventory under this dead nick
                  with on_corpse=1; the winner receives them via UPDATE.
                  If None (NPC drops), the winner receives direct INSERTs and
                  items not claimed simply do not enter inventory.

    Returns True if someone won the autoloot roll, False if no actors found.
    """
    if not item_ids:
        return False

    # NPC level proxy: tier * 5 (tier-1 ≈ level 5, tier-4 ≈ level 20).
    actors = []  # (nick_or_None, npc_inst_or_None, label, level)

    for p in world.players_in_room(room_id):
        if p.get('is_dead'):
            continue
        af = world.db.execute(
            'SELECT autoloot FROM autofight_profiles WHERE nick=? AND world=?',
            (p['nick'], world.world_name)
        ).fetchone()
        if af and af['autoloot']:
            actors.append((p['nick'], None, p['nick'], max(1, p['level'])))

    for inst in world.get_npc_instances_in_room(room_id):
        if inst.get('behavior', 'passive') == 'passive':
            continue
        if inst.get('state') in ('dead', 'respawning'):
            continue
        tier  = min(inst.get('danger_tier', 1), 4)
        level = max(1, tier * 5)
        actors.append((None, inst, inst['name'], level))

    if not actors:
        return False

    total        = sum(a[3] for a in actors)
    winner_label = ProbDist({a[2]: a[3] * 100.0 / total for a in actors}).pick

    winner_nick, winner_npc = None, None
    for a in actors:
        if a[2] == winner_label:
            winner_nick, winner_npc = a[0], a[1]
            break

    # Resolve item names for the broadcast.
    item_names = []
    for iid in item_ids:
        row = world.db.execute(
            'SELECT name FROM items WHERE item_id=?', (iid,)
        ).fetchone()
        if row:
            item_names.append(row['name'])
    if not item_names:
        return False
    loot_str = ', '.join(paint(n, color=C.LOOT) for n in item_names)

    if winner_nick:
        if corpse_nick:
            # Transfer all on_corpse items from the dead player to the winner.
            world.db.execute(
                'UPDATE inventory SET nick=?, on_corpse=0 '
                'WHERE nick=? AND world=? AND on_corpse=1',
                (winner_nick, corpse_nick, world.world_name)
            )
        else:
            # NPC drops: insert directly into winner's inventory.
            for iid in item_ids:
                world.db.execute(
                    'INSERT INTO inventory '
                    '  (nick, world, item_id, quantity, equipped, on_corpse) '
                    'VALUES (?, ?, ?, 1, 0, 0)',
                    (winner_nick, world.world_name, iid)
                )
        _msg_room(channel, world, room_id,
                  paint('[AL] ', color=C.AUTOFIGHT) +
                  paint(winner_nick, bold=True) +
                  ' autoloots ' + loot_str + ' from ' + source_label + '.',
                  C.LOOT)
    else:
        # NPC winner.
        tier      = min(winner_npc.get('danger_tier', 1), 4)
        npc_paint = paint(winner_npc['name'], color=C.NPC[tier], bold=(tier >= 4))
        if corpse_nick:
            # Consume the dead player's corpse items.
            world.db.execute(
                'DELETE FROM inventory WHERE nick=? AND world=? AND on_corpse=1',
                (corpse_nick, world.world_name)
            )
        # else: NPC drops — items simply never enter inventory.
        _msg_room(channel, world, room_id,
                  npc_paint + ' loots ' + loot_str + ' from ' + source_label + '.',
                  C.LOOT)

    return True


def _npc_dies(world, channel, npc_inst, room_id):
    """
    Process NPC death: set to dead/respawning, distribute XP/gold/loot
    among all players who dealt damage, narrate to room.
    """
    iid       = npc_inst['instance_id']
    stats     = npc_inst.get('stats', {})
    tier      = min(npc_inst.get('danger_tier', 1), 4)
    now       = time.time()
    npc_label = paint(npc_inst['name'], color=C.NPC[tier], bold=(tier >= 4))

    # Schedule respawn or permanent death.
    delay = npc_inst.get('respawn_delay') or 0
    if delay > 0:
        world.save_npc_instance(iid, state='dead', current_blood=0,
                                respawn_at=now + delay,
                                next_action_at=now + delay)
    else:
        world.save_npc_instance(iid, state='dead', current_blood=0,
                                next_action_at=now + 86400.0)

    combat   = _npc_combat.pop(iid, None)
    _npc_brains.pop(iid, None)
    _autoplay_state.pop(('npc', iid), None)
    _autoplay_last_act.pop(('npc', iid), None)
    hit_log  = (combat or {}).get('hit_log', {})
    participants = [n for n, d in hit_log.items() if d > 0]

    _msg_room(channel, world, room_id, npc_label + ' has been slain!', C.DEATH)
    world.set_tension(room_id, min(1.0, world.get_tension(room_id) + 0.1))

    if not participants:
        return

    # Karma: +0.01 per participant for killing a hostile NPC.
    hostile_behaviors = {'aggressive', 'aggressive_talker'}
    if npc_inst.get('behavior', '') in hostile_behaviors:
        for nick in participants:
            _accrue_karma(world, nick, 0.01)

    # XP split.
    xp_per = stats.get('xp_value', 0) // max(1, len(participants))
    if xp_per > 0:
        for nick in participants:
            p = world.get_player(nick)
            if p is None:
                continue
            cli = next((c for c in channel.clients if c.nick == nick), None)
            if cli:
                _apply_xp(world, channel, cli, p, xp_per)

    # Gold split.
    gold_total = stats.get('gold_value', random.randint(0, tier * 3))
    gold_per   = gold_total // max(1, len(participants))
    if gold_per > 0:
        currency = 'credits' if world.base_game == 'cyberpunk' else 'gold'
        for nick in participants:
            p = world.get_player(nick)
            if p is None:
                continue
            world.update_player(nick, gold=p['gold'] + gold_per)
            cli = next((c for c in channel.clients if c.nick == nick), None)
            if cli:
                msg(cli, channel,
                    paint('+%d %s' % (gold_per, currency), color=C.CURRENCY))

    # Quest kill progress.
    npc_name_lower = npc_inst['name'].lower()
    currency = 'credits' if world.base_game == 'cyberpunk' else 'gold'
    for nick in participants:
        kill_quests = world.db.execute(
            'SELECT pq.quest_id, pq.progress, q.title, q.objective, '
            '       q.reward_xp, q.reward_gold, q.reward_item '
            'FROM player_quests pq '
            'JOIN quests q ON pq.quest_id=q.quest_id AND pq.world=q.world '
            "WHERE pq.nick=? AND pq.world=? AND pq.status='active'",
            (nick, world.world_name)
        ).fetchall()
        for qrow in kill_quests:
            obj = json.loads(qrow['objective'])
            if obj.get('type') != 'kill':
                continue
            if obj.get('npc_name', '').lower() not in npc_name_lower:
                continue
            needed   = obj.get('count', 1)
            progress = qrow['progress'] + 1
            cli = next((c for c in channel.clients if c.nick == nick), None)
            if progress >= needed:
                world.db.execute(
                    "UPDATE player_quests SET status='complete', progress=? "
                    'WHERE nick=? AND world=? AND quest_id=?',
                    (progress, nick, world.world_name, qrow['quest_id'])
                )
                # Grant rewards.
                p = world.get_player(nick)
                if p and cli:
                    if qrow['reward_xp']:
                        _apply_xp(world, channel, cli, p, qrow['reward_xp'])
                    if qrow['reward_gold']:
                        world.update_player(nick, gold=p['gold'] + qrow['reward_gold'])
                        msg(cli, channel,
                            paint('+%d %s' % (qrow['reward_gold'], currency), color=C.CURRENCY))
                    if qrow['reward_item']:
                        item_row = world.db.execute(
                            'SELECT item_id FROM items WHERE LOWER(name)=? AND world=?',
                            (qrow['reward_item'].lower(), world.world_name)
                        ).fetchone()
                        if item_row:
                            world.db.execute(
                                'INSERT INTO inventory '
                                '  (nick, world, item_id, quantity, equipped, on_corpse) '
                                'VALUES (?, ?, ?, 1, 0, 0)',
                                (nick, world.world_name, item_row['item_id'])
                            )
                            msg(cli, channel,
                                'Quest reward: ' +
                                paint(qrow['reward_item'], color=C.LOOT))
                _accrue_karma(world, nick, 0.1)
                if cli:
                    msg(cli, channel,
                        paint('✦ Mission complete: ', bold=True) +
                        paint(qrow['title'], bold=True), C.SAFE)
            else:
                world.db.execute(
                    'UPDATE player_quests SET progress=? '
                    'WHERE nick=? AND world=? AND quest_id=?',
                    (progress, nick, world.world_name, qrow['quest_id'])
                )
                if cli:
                    msg(cli, channel,
                        paint('• %s: ' % qrow['title'], color=C.SYSTEM) +
                        '%d / %d' % (progress, needed))

    # Loot drops — ProbDist(nothing, drop) per entry; autoloot sampler or
    # round-robin fallback to participants if no one has autoloot on.
    drops = []
    for entry in (npc_inst.get('loot') or []):
        chance = entry.get('chance', 0)
        if chance <= 0:
            continue
        outcome = ProbDist(nothing=max(1, 100 - chance), drop=chance).pick
        if outcome == 'drop':
            item_row = world.db.execute(
                'SELECT item_id FROM items WHERE LOWER(name)=? AND world=?',
                (entry['item_name'].lower(), world.world_name)
            ).fetchone()
            if item_row:
                drops.append(item_row['item_id'])
    if drops:
        # Offer to autoloot actors first; fall back to round-robin if none.
        autolooted = _do_autoloot(world, channel, room_id, drops,
                                   npc_label + "'s remains")
        if not autolooted:
            random.shuffle(drops)
            for idx, item_id in enumerate(drops):
                recipient = participants[idx % len(participants)]
                world.db.execute(
                    'INSERT INTO inventory (nick, world, item_id, quantity, equipped, on_corpse) '
                    'VALUES (?, ?, ?, 1, 0, 0)',
                    (recipient, world.world_name, item_id))
                item_r = world.db.execute(
                    'SELECT name FROM items WHERE item_id=?', (item_id,)).fetchone()
                if item_r:
                    cli = next(
                        (c for c in channel.clients if c.nick == recipient), None)
                    if cli:
                        msg(cli, channel,
                            'You receive ' +
                            paint(item_r['name'], color=C.LOOT) + '.', C.LOOT)


def _resolve_player_attack(world, nick, player, npc_inst):
    """
    Compute one player→NPC attack: roll, warrior bonus, weapon, crits/misses.
    Updates NPC blood and hit_log in _npc_combat.
    Returns (damage_dealt, outcome)  where outcome ∈ {'miss','normal','critical'}.
    Does NOT check for NPC death.
    """
    guild   = player.get('guild') or ''
    family  = _GUILD_FAMILIES.get(guild, '')
    w_dmg   = _equipped_weapon(world, nick)[0]
    w_bonus = (int(_guild_level_for(world, nick, guild) * 0.5)
               if family == 'warrior' else 0)

    npc_defense = npc_inst.get('stats', {}).get('defense', 0)

    # Apply active buffs (berserk → attack bonus; evasion → dodge bonus).
    buff = world._buffs.get(nick, {})
    buff_attack = buff.get('attack', 0) if buff.get('expires_at', 0) > time.time() else 0
    buff_dodge  = buff.get('dodge',  0) if buff.get('expires_at', 0) > time.time() else 0

    # Evasion increases miss chance.
    miss_w = max(1, 8 - buff_dodge)
    outcome = ProbDist(miss=miss_w, normal=77, critical=15).pick

    if outcome == 'miss':
        return 0, 'miss'

    raw    = w_dmg + random.randint(1, 6) + w_bonus + buff_attack
    if outcome == 'critical':
        raw *= 2
    damage = max(0, raw - npc_defense)

    iid = npc_inst['instance_id']
    world.save_npc_instance(iid,
        current_blood=max(0, npc_inst['current_blood'] - damage))
    combat = _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})
    combat['target'] = nick
    combat.setdefault('hit_log', {})[nick] = (
        combat['hit_log'].get(nick, 0) + damage)

    return damage, outcome


def _npc_fresh(world, iid):
    """Re-fetch an NPC instance row as a dict (post-damage)."""
    row = world.db.execute(
        'SELECT i.*, n.name, n.danger_tier, n.behavior, '
        '       n.stats, n.loot, n.respawn_delay '
        'FROM npc_instances i JOIN npcs n ON i.npc_id = n.npc_id '
        'WHERE i.instance_id=?', (iid,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d['stats'] = json.loads(d['stats'] or '{}')
    d['loot']  = json.loads(d['loot']  or '[]')
    return d


# ---------------------------------------------------------------------------
# Combat command handlers
# ---------------------------------------------------------------------------

def _cmd_attack(client, channel, world, player, args):
    """attack <target> — strike an NPC in your current room."""
    nick    = client.nick
    room_id = player['room_id']
    t_name  = args.strip().lower()

    if not t_name:
        msg(client, channel, 'Usage: attack <target>', C.SYSTEM)
        return

    npcs_here = world.get_npc_instances_in_room(room_id)
    # Prefer an NPC already targeting us, then any name match.
    target = None
    for npc in npcs_here:
        if t_name in npc['name'].lower():
            if _npc_combat.get(npc['instance_id'], {}).get('target') == nick:
                target = npc
                break
    if target is None:
        for npc in npcs_here:
            if t_name in npc['name'].lower():
                target = npc
                break

    if target is None:
        msg(client, channel,
            "You don't see '%s' here." % args.strip(), C.SYSTEM)
        return

    iid       = target['instance_id']
    tier      = min(target.get('danger_tier', 1), 4)
    npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))

    # Make sure NPC is in combat mode targeting this player.
    _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
    if target.get('state') in ('idle', 'patrol'):
        world.save_npc_instance(iid, state='aggressive',
                                next_action_at=time.time() + 2.0)

    # Player strikes.
    damage, outcome = _resolve_player_attack(world, nick, player, target)

    # Karma: +0.002 for attacking a hostile, -0.05 for attacking a friendly/passive.
    npc_behavior = target.get('behavior', 'idle')
    if npc_behavior in ('aggressive', 'aggressive_talker'):
        _accrue_karma(world, nick, 0.002)
    elif npc_behavior in ('passive', 'idle'):
        _accrue_karma(world, nick, -0.05)

    if outcome == 'miss':
        msg(client, channel, 'You swing at ' + npc_label + ' and miss.')
    elif outcome == 'critical':
        msg(client, channel,
            paint('Critical hit!', bold=True, color=C.CRIT) +
            ' You strike ' + npc_label + ' for ' +
            paint(str(damage), color=C.DAMAGE_OUT) + ' blood.')
    else:
        msg(client, channel,
            'You strike ' + npc_label + ' for ' +
            paint(str(damage), color=C.DAMAGE_OUT) + ' blood.')

    # Notify others in the room.
    for other in list(channel.clients):
        if other.nick == nick:
            continue
        op = world.get_player(other.nick)
        if op and op.get('room_id') == room_id:
            if outcome == 'miss':
                msg(other, channel,
                    paint(nick, bold=True) + ' misses ' + npc_label + '.')
            else:
                msg(other, channel,
                    paint(nick, bold=True) + ' strikes ' + npc_label +
                    ' for ' + paint(str(damage), color=C.DAMAGE_OUT) + ' blood.')

    # Always consume the defend flag, whether or not NPC dies.
    defending = nick in world._defending
    world._defending.discard(nick)

    # Check NPC death.
    fresh = _npc_fresh(world, iid)
    if fresh and fresh['current_blood'] <= 0:
        _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # Immediate NPC counter-attack — skip if NPC is stunned.
    if (fresh or target).get('next_action_at', 0) > time.time():
        world.commit()
        return

    npc_stats  = (fresh or target).get('stats', {})
    c_dmg      = max(1, npc_stats.get('attack', 2) + random.randint(1, 6))
    c_dmg      = max(0, c_dmg - _player_defense(world, nick))
    if defending:
        c_dmg  = max(0, c_dmg // 2)

    cur_p = world.get_player(nick)
    if cur_p:
        new_blood = max(0, cur_p['blood'] - c_dmg)
        world.update_player(nick, blood=new_blood)

        defend_tag = '  ' + paint('(Defended!)', color=C.SAFE) if defending else ''
        msg(client, channel,
            npc_label + ' retaliates for ' +
            paint(str(c_dmg), color=C.DAMAGE_IN) + ' blood.' + defend_tag +
            '  (%d/%d blood)' % (new_blood, cur_p['max_blood']))

        for other in list(channel.clients):
            if other.nick == nick:
                continue
            op = world.get_player(other.nick)
            if op and op.get('room_id') == room_id:
                msg(other, channel,
                    npc_label + ' retaliates against ' +
                    paint(nick, bold=True) + ' for ' +
                    paint(str(c_dmg), color=C.DAMAGE_IN) + ' blood.')

        if new_blood <= 0:
            delay = max(1.0, 10.0 / max(1, cur_p['level']))
            world.update_player(nick, is_dead=1, blood=0,
                                respawn_at=time.time() + delay)
            _msg_room(channel, world, room_id,
                paint(nick, bold=True) + ' has been slain!', C.DEATH)
            msg(client, channel,
                paint('You are dead.', bold=True) +
                ' Respawn in %d seconds.' % int(delay), C.DEAD)
            corpse_items = _mark_player_corpse(world, nick)
            if corpse_items:
                _do_autoloot(world, channel, room_id, corpse_items,
                             paint(nick, bold=True) + "'s corpse",
                             corpse_nick=nick)

    world.commit()


def _cmd_flee(client, channel, world, player, args):
    """flee — attempt to escape from combat."""
    nick    = client.nick
    room_id = player['room_id']

    npcs_here = world.get_npc_instances_in_room(room_id)
    hostile   = [n for n in npcs_here
                 if n.get('state') == 'aggressive'
                 or _npc_combat.get(n['instance_id'], {}).get('target') == nick]

    if not hostile:
        msg(client, channel, 'You are not in combat.', C.SYSTEM)
        return

    stamina = player.get('stamina', 0)
    if stamina < 2:
        msg(client, channel,
            "You're too exhausted to flee! (need 2 stamina)", C.SYSTEM)
        return

    world.update_player(nick, stamina=max(0, stamina - 2))

    # Flee chance: base 60% + 2%/level, -10% per hostile NPC.
    chance = min(90, max(10, 60 + player.get('level', 1) * 2 - len(hostile) * 10))

    if random.randint(1, 100) <= chance:
        room  = world.get_room(room_id)
        exits = room.get('exits', {}) if room else {}
        if not exits:
            msg(client, channel, 'There is nowhere to flee!', C.SYSTEM)
            return
        dest_id   = random.choice(list(exits.values()))
        dest_room = world.get_room(dest_id)
        world.update_player(nick, room_id=dest_id)
        if dest_room and dest_room.get('is_safe'):
            world.update_player(nick, last_safe_room_id=dest_id)
        world.commit()
        _msg_room(channel, world, room_id,
            paint(nick, bold=True) + ' flees the battle!')
        dest_name = dest_room['name'] if dest_room else 'somewhere'
        msg(client, channel,
            paint('You flee to %s!' % dest_name, bold=True), C.SAFE)
        _show_room(client, channel, world, dest_id)
    else:
        msg(client, channel, paint('You fail to escape!', bold=True), C.DAMAGE_IN)
        cur_p = world.get_player(nick)
        for npc in hostile:
            if cur_p is None or cur_p.get('is_dead'):
                break
            nstats    = npc.get('stats', {})
            c_dmg     = max(1, nstats.get('attack', 2) + random.randint(1, 6))
            c_dmg     = max(0, c_dmg - _player_defense(world, nick))
            new_blood = max(0, cur_p['blood'] - c_dmg)
            world.update_player(nick, blood=new_blood)
            tier      = min(npc.get('danger_tier', 1), 4)
            npc_label = paint(npc['name'], color=C.NPC[tier], bold=(tier >= 4))
            msg(client, channel,
                npc_label + ' strikes you for ' +
                paint(str(c_dmg), color=C.DAMAGE_IN) + ' blood.  ' +
                '(%d/%d blood)' % (new_blood, cur_p['max_blood']))
            if new_blood <= 0:
                delay = max(1.0, 10.0 / max(1, cur_p['level']))
                world.update_player(nick, is_dead=1, blood=0,
                                    respawn_at=time.time() + delay)
                _msg_room(channel, world, room_id,
                    paint(nick, bold=True) + ' is cut down while fleeing!', C.DEATH)
                msg(client, channel,
                    paint('You are dead.', bold=True) +
                    ' Respawn in %d seconds.' % int(delay), C.DEAD)
                corpse_items = _mark_player_corpse(world, nick)
                if corpse_items:
                    _do_autoloot(world, channel, room_id, corpse_items,
                                 paint(nick, bold=True) + "'s corpse",
                                 corpse_nick=nick)
                break
            cur_p = world.get_player(nick)
        world.commit()


def _cmd_defend(client, channel, world, player, args):
    """defend — halve the next incoming hit this round."""
    nick = client.nick
    if nick in world._defending:
        msg(client, channel, 'You are already defending.', C.SYSTEM)
        return
    world._defending.add(nick)
    msg(client, channel,
        paint('You raise your guard.', bold=True) +
        ' Next incoming attack will be halved.', C.SAFE)


def _cast_spell(client, channel, world, player, spell_name, target_arg=''):
    """Resolve a named spell/ability. Called by _cmd_use."""
    nick    = client.nick
    room_id = player['room_id']
    guild   = player.get('guild') or ''
    gl      = _guild_level_for(world, nick, guild)
    stamina = player.get('stamina', 0)

    entry = _SPELL_CANON.get(spell_name.lower())
    if entry is None:
        msg(client, channel, "Unknown ability '%s'." % spell_name, C.SYSTEM)
        return
    canon, cost = entry

    if stamina < cost:
        msg(client, channel,
            'Not enough stamina. (need %d, have %d)' % (cost, stamina), C.SYSTEM)
        return

    world.update_player(nick, stamina=max(0, stamina - cost))
    spell_label = paint(spell_name, bold=True, color=C.SPELL)

    # ── heal / patch up ──────────────────────────────────────────────────────
    if canon == 'heal':
        heal      = int(10 + gl * 2)
        new_blood = min(player['blood'] + heal, player['max_blood'])
        world.update_player(nick, blood=new_blood)
        _accrue_karma(world, nick, 0.05)
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('+%d blood' % heal, color=C.HEAL) +
            '  (%d/%d)' % (new_blood, player['max_blood']), C.HEAL)
        return

    # ── magic missile / hack ─────────────────────────────────────────────────
    if canon == 'magic_missile':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target    = None
        if target_arg:
            for n in npcs_here:
                if target_arg.lower() in n['name'].lower():
                    target = n
                    break
        if target is None:
            # Prefer NPC targeting us, then any NPC in room.
            for n in npcs_here:
                if _npc_combat.get(n['instance_id'], {}).get('target') == nick:
                    target = n
                    break
        if target is None and npcs_here:
            target = npcs_here[0]
        if target is None:
            msg(client, channel, 'There is nothing to target here.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)  # refund
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        damage    = random.randint(1, 8) + gl  # magic ignores defense
        world.save_npc_instance(iid,
            current_blood=max(0, target['current_blood'] - damage))
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        _npc_combat[iid].setdefault('hit_log', {})[nick] = (
            _npc_combat[iid]['hit_log'].get(nick, 0) + damage)
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        msg(client, channel,
            spell_label + ': You blast ' + npc_label + ' for ' +
            paint(str(damage), color=C.DAMAGE_OUT) + ' blood.', C.DAMAGE_OUT)
        fresh = _npc_fresh(world, iid)
        if fresh and fresh['current_blood'] <= 0:
            _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── fireball / system crash — AoE ────────────────────────────────────────
    if canon == 'fireball':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'There is nothing to hit.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        total_dmg = 0
        base_dmg  = random.randint(4, 8) + gl
        for npc in npcs_here:
            iid   = npc['instance_id']
            tier  = min(npc.get('danger_tier', 1), 4)
            npc_l = paint(npc['name'], color=C.NPC[tier], bold=(tier >= 4))
            dmg   = max(0, base_dmg - npc.get('stats', {}).get('defense', 0))
            world.save_npc_instance(iid,
                current_blood=max(0, npc['current_blood'] - dmg))
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=time.time() + 2.0)
            total_dmg += dmg
        msg(client, channel,
            spell_label + ': You unleash devastation (%d NPCs hit, ~%d blood each).'
            % (len(npcs_here), base_dmg), C.DAMAGE_OUT)
        for npc in npcs_here:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── taunt / provoke ───────────────────────────────────────────────────────
    if canon == 'taunt':
        npcs_here = world.get_npc_instances_in_room(room_id)
        for npc in npcs_here:
            iid = npc['instance_id']
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=time.time() + 1.5)
        world.commit()
        msg(client, channel,
            spell_label + ': You taunt every enemy in the room!', C.DAMAGE_IN)
        _msg_room(channel, world, room_id,
            paint(nick, bold=True) + ' taunts all enemies — they focus on them!')
        return

    # ── stealth / ghost protocol ──────────────────────────────────────────────
    if canon == 'stealth':
        world.add_status_effect(nick, None, 'stealth', 1, 30, nick)
        world.commit()
        msg(client, channel,
            spell_label + ': You fade into the shadows.', C.SAFE)
        return

    # ── backstab / execution ──────────────────────────────────────────────────
    if canon == 'backstab':
        # Requires stealth status.
        effects = [e['effect'] for e in world.get_status_effects(nick=nick)]
        if 'stealth' not in effects:
            msg(client, channel,
                spell_label + ' requires stealth.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)  # refund
            world.commit()
            return
        npcs_here = world.get_npc_instances_in_room(room_id)
        target    = None
        if target_arg:
            for n in npcs_here:
                if target_arg.lower() in n['name'].lower():
                    target = n
                    break
        if target is None and npcs_here:
            target = npcs_here[0]
        if target is None:
            msg(client, channel, 'There is nothing to backstab.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        w_dmg     = _equipped_weapon(world, nick)[0]
        damage    = max(1, (w_dmg + random.randint(1, 6)) * 3)
        world.save_npc_instance(iid,
            current_blood=max(0, target['current_blood'] - damage))
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        _npc_combat[iid].setdefault('hit_log', {})[nick] = (
            _npc_combat[iid]['hit_log'].get(nick, 0) + damage)
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        # Remove stealth.
        world.db.execute(
            'DELETE FROM status_effects WHERE nick=? AND world=? AND effect="stealth"',
            (nick, world.world_name))
        msg(client, channel,
            spell_label + ': You strike ' + npc_label + ' from the shadows for ' +
            paint(str(damage), color=C.DAMAGE_OUT) + ' blood! Stealth broken.',
            C.DAMAGE_OUT)
        fresh = _npc_fresh(world, iid)
        if fresh and fresh['current_blood'] <= 0:
            _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── shield bash / flash bang ──────────────────────────────────────────────
    if canon == 'shield_bash':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target    = None
        for n in npcs_here:
            if _npc_combat.get(n['instance_id'], {}).get('target') == nick:
                target = n
                break
        if target is None and npcs_here:
            target = npcs_here[0]
        if target is None:
            msg(client, channel, 'No target in range.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        # Stun the NPC for 6 seconds.
        world.save_npc_instance(iid,
            state='aggressive', next_action_at=time.time() + 6.0)
        # Small damage.
        dmg = max(1, random.randint(1, 4))
        world.save_npc_instance(iid,
            current_blood=max(0, target['current_blood'] - dmg))
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        _npc_combat[iid].setdefault('hit_log', {})[nick] = (
            _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
        world.commit()
        msg(client, channel,
            spell_label + ': You stun ' + npc_label +
            ' for 6 seconds! (%d blood)' % dmg, C.DAMAGE_OUT)
        return

    # ── smite / shock ─────────────────────────────────────────────────────────
    if canon == 'smite':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target    = None
        for n in npcs_here:
            if _npc_combat.get(n['instance_id'], {}).get('target') == nick:
                target = n
                break
        if target is None and npcs_here:
            target = npcs_here[0]
        if target is None:
            msg(client, channel, 'No target in range.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        base_d    = random.randint(4, 8) + gl
        # Double damage vs undead (behavior tag check) or cyborgs.
        undead_tags = {'undead', 'skeleton', 'zombie', 'lich'}
        cyborg_tags = {'cyborg', 'drone', 'android'}
        npc_name_l  = target['name'].lower()
        double      = (world.base_game == 'default'
                       and any(t in npc_name_l for t in undead_tags))
        double      = double or (world.base_game == 'cyberpunk'
                                 and any(t in npc_name_l for t in cyborg_tags))
        damage      = base_d * 2 if double else base_d
        world.save_npc_instance(iid,
            current_blood=max(0, target['current_blood'] - damage))
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        _npc_combat[iid].setdefault('hit_log', {})[nick] = (
            _npc_combat[iid]['hit_log'].get(nick, 0) + damage)
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        bonus_tag = paint(' (DOUBLE DAMAGE)', bold=True, color=C.CRIT) if double else ''
        msg(client, channel,
            spell_label + ': You smite ' + npc_label + ' for ' +
            paint(str(damage), color=C.DAMAGE_OUT) + ' blood.' + bonus_tag,
            C.DAMAGE_OUT)
        fresh = _npc_fresh(world, iid)
        if fresh and fresh['current_blood'] <= 0:
            _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── ice storm / ice breaker — AoE slow ───────────────────────────────────
    if canon == 'ice_storm':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'There is nothing to target.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        base_dmg = random.randint(3, 7) + gl
        for npc in npcs_here:
            iid  = npc['instance_id']
            dmg  = max(0, base_dmg - npc.get('stats', {}).get('defense', 0) // 2)
            world.save_npc_instance(iid,
                current_blood=max(0, npc['current_blood'] - dmg),
                next_action_at=time.time() + 4.0)   # slowed
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive')
        msg(client, channel,
            spell_label + ': Ice shatters across the room! (%d NPCs slowed).'
            % len(npcs_here), C.DAMAGE_OUT)
        for npc in npcs_here:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── berserk / combat stims — attack buff ──────────────────────────────────
    if canon == 'berserk':
        expires = time.time() + 30.0
        world._buffs[nick] = {
            'attack':    int(3 + gl),
            'defense':   0,
            'dodge':     0,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('Berserk!', bold=True, color=C.DAMAGE_OUT) +
            ' +%d attack for 30 seconds.' % int(3 + gl), C.DAMAGE_OUT)
        return

    # ── whirlwind / suppressive fire — multi-hit ──────────────────────────────
    if canon == 'whirlwind':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'There is nothing to hit.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        w_dmg = _equipped_weapon(world, nick)[0]
        hits  = min(len(npcs_here), 2 + gl // 3)
        targets_hit = random.sample(npcs_here, min(hits, len(npcs_here)))
        total_dmg   = 0
        for npc in targets_hit:
            iid = npc['instance_id']
            dmg = max(1, w_dmg + random.randint(1, 4))
            world.save_npc_instance(iid,
                current_blood=max(0, npc['current_blood'] - dmg))
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=time.time() + 2.0)
            total_dmg += dmg
        msg(client, channel,
            spell_label + ': You strike %d enemies for %d total blood!'
            % (len(targets_hit), total_dmg), C.DAMAGE_OUT)
        for npc in targets_hit:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── bless / overclock — defense buff ──────────────────────────────────────
    if canon == 'bless':
        expires = time.time() + 30.0
        world._buffs[nick] = {
            'attack':    0,
            'defense':   int(2 + gl),
            'dodge':     0,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('Blessed!', bold=True, color=C.SAFE) +
            ' +%d defense for 30 seconds.' % int(2 + gl), C.SAFE)
        return

    # ── evasion / ghost protocol (dodge buff) ─────────────────────────────────
    if canon == 'evasion':
        expires = time.time() + 20.0
        world._buffs[nick] = {
            'attack':    0,
            'defense':   0,
            'dodge':     5,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('Evasion active!', bold=True, color=C.SAFE) +
            ' Reduced miss chance for 20 seconds.', C.SAFE)
        return

    # ── teleport / jack in — warp to last safe room ───────────────────────────
    if canon == 'teleport':
        world_rec = world.get_world()
        dest_id   = (player.get('last_safe_room_id')
                     or world_rec['start_room_id'])
        dest_room = world.get_room(dest_id)
        if dest_id == room_id:
            msg(client, channel, 'You are already at a safe location.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        world.update_player(nick, room_id=dest_id)
        _msg_room(channel, world, room_id,
            paint(nick, bold=True) + ' vanishes in a flash!')
        world.commit()
        dest_name = dest_room['name'] if dest_room else 'somewhere safe'
        msg(client, channel,
            spell_label + ': You teleport to ' +
            paint(dest_name, bold=True) + '.', C.SAFE)
        _show_room(client, channel, world, dest_id)
        return

    # ── pickpocket — steal gold from an NPC ───────────────────────────────────
    if canon == 'pickpocket':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'There is no one to pickpocket.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        target_npc = npcs_here[0]
        npc_tier   = min(target_npc.get('danger_tier', 1), 4)
        npc_label2 = paint(target_npc['name'], color=C.NPC[npc_tier],
                           bold=(npc_tier >= 4))
        stolen = random.randint(1, max(1, npc_tier * 2))
        currency = 'credits' if world.base_game == 'cyberpunk' else 'gold'
        p_fresh = world.get_player(nick)
        world.update_player(nick, gold=(p_fresh or player)['gold'] + stolen)
        world.commit()
        msg(client, channel,
            spell_label + ': You lift ' +
            paint('+%d %s' % (stolen, currency), color=C.CURRENCY) +
            ' from ' + npc_label2 + '.', C.CURRENCY)
        return

    # ── resurrect — revive a dead player in the room ──────────────────────────
    if canon == 'resurrect':
        family = _GUILD_FAMILIES.get(guild, '')
        if family != 'cleric':
            msg(client, channel,
                spell_label + ' can only be cast by Clerics/Ripperdocs.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        dead_target = None
        for c in channel.clients:
            if c.nick == nick:
                continue
            tp = world.get_player(c.nick)
            if tp and tp.get('is_dead') and tp.get('room_id') == room_id:
                dead_target = (c, tp)
                break
        if dead_target is None:
            msg(client, channel, 'There is no one to resurrect here.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        t_client, t_player = dead_target
        world.update_player(t_client.nick,
            is_dead=0, blood=max(1, t_player['max_blood'] // 4),
            respawn_at=None)
        world.commit()
        msg(client, channel,
            spell_label + ': You resurrect ' +
            paint(t_client.nick, bold=True) + '!', C.HEAL)
        msg(t_client, channel,
            paint(nick, bold=True) + ' brings you back from the dead!', C.HEAL)
        _show_room(t_client, channel, world, room_id)
        return

    # ── chain lightning / arc discharge — bouncing lightning ──────────────────
    if canon == 'chain_lightning':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'No targets in range.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        chain    = npcs_here[:min(3, len(npcs_here))]
        base_dmg = random.randint(6, 10) + gl
        msgs     = []
        for idx, npc in enumerate(chain):
            iid   = npc['instance_id']
            dmg   = max(1, base_dmg >> idx)   # halves each bounce
            tier  = min(npc.get('danger_tier', 1), 4)
            nl    = paint(npc['name'], color=C.NPC[tier], bold=(tier >= 4))
            world.save_npc_instance(iid,
                current_blood=max(0, npc['current_blood'] - dmg))
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=time.time() + 2.0)
            msgs.append('%s (%d)' % (nl, dmg))
        msg(client, channel,
            spell_label + ': Lightning arcs — ' + ' → '.join(msgs),
            C.DAMAGE_OUT)
        for npc in chain:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── drain / data siphon — damage + restore own stamina ───────────────────
    if canon == 'drain':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'Nothing to drain.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        dmg       = random.randint(3, 6) + gl
        world.save_npc_instance(iid,
            current_blood=max(0, target['current_blood'] - dmg))
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        _npc_combat[iid].setdefault('hit_log', {})[nick] = (
            _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        stam_gain = min(3 + gl // 2, player.get('max_stamina', 10) - stamina)
        stam_gain = max(0, stam_gain)
        world.update_player(nick, stamina=stamina + stam_gain)
        msg(client, channel,
            spell_label + ': You drain ' + npc_label +
            ' for ' + paint(str(dmg), color=C.DAMAGE_OUT) + ' blood' +
            (' and recover ' + paint('+%d stamina' % stam_gain, color=C.SAFE)
             if stam_gain else '') + '.', C.DAMAGE_OUT)
        fresh = _npc_fresh(world, iid)
        if fresh and fresh['current_blood'] <= 0:
            _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── detect / analyze — reveal NPC stats ──────────────────────────────────
    if canon == 'detect':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'There is nothing to analyze here.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        world.commit()
        for npc in npcs_here:
            s     = npc.get('stats', {})
            tier  = min(npc.get('danger_tier', 1), 4)
            nl    = paint(npc['name'], color=C.NPC[tier], bold=(tier >= 4))
            pct   = int(npc['current_blood'] * 100
                        / max(1, s.get('max_blood', npc['current_blood'])))
            msg(client, channel,
                spell_label + ' [' + nl + ']  '
                'Blood: %d/%d (%d%%)  ATK:%d  DEF:%d  Tier:%d' % (
                    npc['current_blood'], s.get('max_blood', '?'),
                    pct, s.get('attack', 0), s.get('defense', 0),
                    npc.get('danger_tier', 1)), C.SYSTEM)
        return

    # ── mend / nano-heal — healing regen over time ────────────────────────────
    if canon == 'mend':
        heal_per = max(1, 2 + gl // 2)
        ticks    = 10 + gl
        world.add_status_effect(nick, None, 'regen', heal_per, ticks, nick)
        _accrue_karma(world, nick, 0.05)
        world.commit()
        msg(client, channel,
            spell_label + ': Regenerating ' +
            paint('+%d blood/tick' % heal_per, color=C.HEAL) +
            ' for %d ticks.' % ticks, C.HEAL)
        return

    # ── curse / system virus — apply poison DoT to NPC ───────────────────────
    if canon == 'curse':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'No target to curse.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        sev       = max(1, 1 + gl // 3)
        ticks     = 8 + gl
        world.add_status_effect(None, iid, 'poison', sev, ticks, nick)
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        world.commit()
        msg(client, channel,
            spell_label + ': ' + npc_label +
            ' is cursed! (%d poison × %d ticks)' % (sev, ticks),
            C.DAMAGE_OUT)
        return

    # ── blind / sensor jam — delay NPC's next action ─────────────────────────
    if canon == 'blind':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'No target in range.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        duration  = 4.0 + gl * 0.5
        world.save_npc_instance(iid,
            state='aggressive',
            next_action_at=time.time() + duration)
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        world.commit()
        msg(client, channel,
            spell_label + ': ' + npc_label +
            ' is blinded for %.0f seconds!' % duration, C.DAMAGE_OUT)
        return

    # ── leech / power drain — deal damage + heal self ────────────────────────
    if canon == 'leech':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'Nothing to leech from.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid       = target['instance_id']
        tier      = min(target.get('danger_tier', 1), 4)
        npc_label = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        dmg       = random.randint(4, 8) + gl
        heal      = dmg // 2
        world.save_npc_instance(iid,
            current_blood=max(0, target['current_blood'] - dmg))
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        _npc_combat[iid].setdefault('hit_log', {})[nick] = (
            _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        new_blood = min(player['blood'] + heal, player['max_blood'])
        world.update_player(nick, blood=new_blood)
        msg(client, channel,
            spell_label + ': You leech ' +
            paint(str(dmg), color=C.DAMAGE_OUT) + ' blood from ' + npc_label +
            ', healing ' + paint('+%d' % heal, color=C.HEAL) + '.',
            C.DAMAGE_OUT)
        fresh = _npc_fresh(world, iid)
        if fresh and fresh['current_blood'] <= 0:
            _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── rally / broadcast boost — heal all party in room ─────────────────────
    if canon == 'rally':
        heal = int(8 + gl * 2)
        healed = 0
        for c in list(channel.clients):
            if c.nick not in world._online:
                continue
            tp = world.get_player(c.nick)
            if tp and tp.get('room_id') == room_id and not tp.get('is_dead'):
                nb = min(tp['blood'] + heal, tp['max_blood'])
                world.update_player(c.nick, blood=nb)
                healed += 1
                if c.nick == nick:
                    msg(c, channel,
                        spell_label + ': You rally the party — ' +
                        paint('+%d blood' % heal, color=C.HEAL), C.HEAL)
                else:
                    msg(c, channel,
                        paint(nick, bold=True) + ' rallies! ' +
                        paint('+%d blood' % heal, color=C.HEAL), C.HEAL)
        _accrue_karma(world, nick, 0.05)
        world.commit()
        return

    # ── poison blade / nano-toxin — next attack applies bleed ────────────────
    if canon == 'poison_blade':
        world.add_status_effect(nick, None, 'poison_blade', 1, 1, nick)
        world.commit()
        msg(client, channel,
            spell_label + ': Your next attack applies ' +
            paint('bleed', color=C.DAMAGE_IN) + '.', C.DAMAGE_OUT)
        return

    # ── stone skin / hardened chassis — high defense buff ────────────────────
    if canon == 'stone_skin':
        expires = time.time() + 25.0
        world._buffs[nick] = {
            'attack':    0,
            'defense':   int(5 + gl),
            'dodge':     0,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('Stone Skin!', bold=True, color=C.SAFE) +
            ' +%d defense for 25 seconds.' % int(5 + gl), C.SAFE)
        return

    # =========================================================================
    # Tier-2 spells (levels 13-21)
    # =========================================================================

    # ── bind / root access — extended stun, prevents NPC fleeing ─────────────
    if canon == 'bind':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'Nothing to bind.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid      = target['instance_id']
        tier     = min(target.get('danger_tier', 1), 4)
        nl       = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        duration = 8.0 + gl * 0.5
        world.save_npc_instance(iid, state='aggressive',
                                next_action_at=time.time() + duration)
        # Mark NPC as rooted so it can't flee.
        world.add_status_effect(None, iid, 'rooted', 1, int(duration), nick)
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        world.commit()
        msg(client, channel,
            spell_label + ': ' + nl +
            ' is bound for %.0f seconds!' % duration, C.DAMAGE_OUT)
        return

    # ── shatter / deconstruct — ignores all NPC defense ──────────────────────
    if canon == 'shatter':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'No target in range.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid      = target['instance_id']
        tier     = min(target.get('danger_tier', 1), 4)
        nl       = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        w_dmg    = _equipped_weapon(world, nick)[0]
        damage   = max(1, w_dmg + random.randint(2, 8) + gl)  # no defense subtracted
        world.save_npc_instance(iid,
            current_blood=max(0, target['current_blood'] - damage))
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        _npc_combat[iid].setdefault('hit_log', {})[nick] = (
            _npc_combat[iid]['hit_log'].get(nick, 0) + damage)
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        msg(client, channel,
            spell_label + ': You shatter ' + nl + '\'s defences for ' +
            paint(str(damage), color=C.DAMAGE_OUT) + ' blood (armor ignored)!',
            C.DAMAGE_OUT)
        fresh = _npc_fresh(world, iid)
        if fresh and fresh['current_blood'] <= 0:
            _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── blood pact / risk protocol — sacrifice blood for attack buff ──────────
    if canon == 'blood_pact':
        sacrifice = max(1, player['max_blood'] // 6)
        new_blood = max(1, player['blood'] - sacrifice)
        if player['blood'] <= sacrifice:
            msg(client, channel,
                'You need more blood to make the pact!', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        expires = time.time() + 40.0
        world._buffs[nick] = {
            'attack':    int(6 + gl),
            'defense':   0,
            'dodge':     0,
            'expires_at': expires,
        }
        world.update_player(nick, blood=new_blood)
        world.commit()
        msg(client, channel,
            spell_label + ': You sacrifice ' +
            paint(str(sacrifice) + ' blood', color=C.DAMAGE_IN) +
            ' for ' + paint('+%d attack' % int(6 + gl), color=C.DAMAGE_OUT) +
            ' for 40 seconds.', C.DAMAGE_OUT)
        return

    # ── ward / firewall — absorb the next incoming hit ────────────────────────
    if canon == 'ward':
        expires = time.time() + 15.0
        world._buffs[nick] = {
            'attack':    0,
            'defense':   0,
            'dodge':     0,
            'ward':      True,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('Warded!', bold=True, color=C.SAFE) +
            ' Your next incoming hit will be fully absorbed.', C.SAFE)
        return

    # ── time stop / system freeze — stun ALL NPCs in room ────────────────────
    if canon == 'time_stop':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'There is nothing here to stop.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        duration = 5.0 + gl * 0.3
        for npc in npcs_here:
            iid = npc['instance_id']
            world.save_npc_instance(iid, next_action_at=time.time() + duration)
            if npc.get('state') == 'aggressive':
                _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})
        world.commit()
        msg(client, channel,
            spell_label + ': Time freezes! '
            'All %d enemies stunned for %.0f seconds.' % (len(npcs_here), duration),
            C.DAMAGE_OUT)
        return

    # ── meteor / data nuke — devastating AoE ─────────────────────────────────
    if canon == 'meteor':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'There is nothing to hit.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        base_dmg  = random.randint(10, 16) + gl * 2
        total_dmg = 0
        for npc in npcs_here:
            iid  = npc['instance_id']
            dmg  = max(1, base_dmg - npc.get('stats', {}).get('defense', 0) // 2)
            world.save_npc_instance(iid,
                current_blood=max(0, npc['current_blood'] - dmg))
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=time.time() + 2.0)
            total_dmg += dmg
        msg(client, channel,
            spell_label + ': A meteor strikes! '
            '%d enemies take ~%d blood each (%d total).' % (
                len(npcs_here), base_dmg, total_dmg), C.DAMAGE_OUT)
        for npc in npcs_here:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── absorb / data harvest — steal partial XP from living NPC ─────────────
    if canon == 'absorb':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'Nothing to absorb.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid     = target['instance_id']
        tier    = min(target.get('danger_tier', 1), 4)
        nl      = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        xp_base = target.get('stats', {}).get('xp_value', 0)
        xp_gain = max(1, xp_base // 3 + gl)
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 3.0)
        _apply_xp(world, channel, client, player, xp_gain)
        world.commit()
        msg(client, channel,
            spell_label + ': You drain experience from ' + nl + '.', C.XP)
        return

    # ── consecrate / overwrite — AoE magic damage + self-heal ────────────────
    if canon == 'consecrate':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'Nothing to consecrate.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        total_dmg = 0
        base_dmg  = random.randint(5, 9) + gl
        for npc in npcs_here:
            iid = npc['instance_id']
            dmg = max(0, base_dmg - npc.get('stats', {}).get('defense', 0) // 2)
            world.save_npc_instance(iid,
                current_blood=max(0, npc['current_blood'] - dmg))
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=time.time() + 2.0)
            total_dmg += dmg
        heal     = total_dmg // 2
        new_b    = min(player['blood'] + heal, player['max_blood'])
        world.update_player(nick, blood=new_b)
        msg(client, channel,
            spell_label + ': Holy fire scorches %d enemies (%d total dmg), '
            'healing you for ' + paint('+%d' % heal, color=C.HEAL) + '.' % (
                len(npcs_here), total_dmg), C.DAMAGE_OUT)
        for npc in npcs_here:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── spirit link / sync link — party defense buff + small heal ────────────
    if canon == 'spirit_link':
        heal    = int(5 + gl)
        def_bon = int(2 + gl // 2)
        expires = time.time() + 20.0
        healed  = 0
        for c in list(channel.clients):
            if c.nick not in world._online:
                continue
            tp = world.get_player(c.nick)
            if tp and tp.get('room_id') == room_id and not tp.get('is_dead'):
                nb = min(tp['blood'] + heal, tp['max_blood'])
                world.update_player(c.nick, blood=nb)
                # Apply defense buff to each party member.
                world._buffs[c.nick] = {
                    'attack':     0,
                    'defense':    def_bon,
                    'dodge':      0,
                    'expires_at': expires,
                }
                healed += 1
                notice = (spell_label + ': Spirit link — +%d blood, +%d defense (20s).'
                          % (heal, def_bon))
                msg(c, channel, notice, C.SAFE)
        world.commit()
        return

    # ── shockwave / emp burst — push all NPCs to adjacent rooms ──────────────
    if canon == 'shockwave':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'Nothing to shockwave.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        room_rec = world.get_room(room_id)
        exits    = room_rec.get('exits', {}) if room_rec else {}
        pushed   = 0
        for npc in npcs_here:
            iid = npc['instance_id']
            if exits:
                dest = random.choice(list(exits.values()))
                world.save_npc_instance(iid, room_id=dest, state='fleeing',
                                        next_action_at=time.time() + 5.0)
                _npc_combat.pop(iid, None)
                pushed += 1
            else:
                # No exits — just stun instead.
                world.save_npc_instance(iid, next_action_at=time.time() + 6.0)
        world.commit()
        if exits and pushed:
            msg(client, channel,
                spell_label + ': A concussive blast scatters ' +
                paint(str(pushed), bold=True) + ' enemies to adjacent areas!',
                C.DAMAGE_OUT)
        else:
            msg(client, channel,
                spell_label + ': The shockwave stuns everything in the room!',
                C.DAMAGE_OUT)
        return

    # =========================================================================
    # Tier-3 spells (levels 23-31)
    # =========================================================================

    # ── apocalypse / zero day — instant-kill <30% hp, heavy damage rest ───────
    if canon == 'apocalypse':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'Nothing to apocalypse.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        base_dmg = random.randint(12, 20) + gl * 2
        dead_names, hit_names = [], []
        for npc in npcs_here:
            iid   = npc['instance_id']
            s     = npc.get('stats', {})
            max_b = s.get('max_blood', max(1, npc['current_blood']))
            tier  = min(npc.get('danger_tier', 1), 4)
            nl    = paint(npc['name'], color=C.NPC[tier], bold=(tier >= 4))
            pct   = npc['current_blood'] / max(1, max_b)
            if pct <= 0.30:
                world.save_npc_instance(iid, current_blood=0)
                _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
                _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                    _npc_combat[iid]['hit_log'].get(nick, 0) + npc['current_blood'])
                dead_names.append(nl)
            else:
                dmg = max(1, base_dmg - s.get('defense', 0) // 2)
                world.save_npc_instance(iid,
                    current_blood=max(0, npc['current_blood'] - dmg))
                _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
                _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                    _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
                if npc.get('state') in ('idle', 'patrol'):
                    world.save_npc_instance(iid, state='aggressive',
                                            next_action_at=time.time() + 2.0)
                hit_names.append(nl)
        parts = []
        if dead_names:
            parts.append(paint('Obliterated: ', bold=True) + ', '.join(dead_names))
        if hit_names:
            parts.append('Damaged: ' + ', '.join(hit_names))
        msg(client, channel,
            spell_label + ': ' + ('  '.join(parts) or 'Nothing happened.'),
            C.DAMAGE_OUT)
        for npc in npcs_here:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── time warp / clock spike — attack buff (bonus damage) 20s ─────────────
    if canon == 'time_warp':
        expires = time.time() + 20.0
        bonus   = int(8 + gl)
        world._buffs[nick] = {
            'attack':    bonus,
            'defense':   0,
            'dodge':     0,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': Time accelerates — ' +
            paint('+%d attack' % bonus, color=C.DAMAGE_OUT) +
            ' for 20 seconds.', C.DAMAGE_OUT)
        return

    # ── soul steal / identity theft — copy NPC's ATK as attack buff ──────────
    if canon == 'soul_steal':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'Nothing to steal from.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid      = target['instance_id']
        tier     = min(target.get('danger_tier', 1), 4)
        nl       = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        npc_atk  = target.get('stats', {}).get('attack', 2)
        expires  = time.time() + 20.0
        world._buffs[nick] = {
            'attack':    npc_atk,
            'defense':   0,
            'dodge':     0,
            'expires_at': expires,
        }
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
        if target.get('state') in ('idle', 'patrol'):
            world.save_npc_instance(iid, state='aggressive',
                                    next_action_at=time.time() + 2.0)
        world.commit()
        msg(client, channel,
            spell_label + ': You steal the power of ' + nl + '! ' +
            paint('+%d attack' % npc_atk, color=C.DAMAGE_OUT) + ' for 20 seconds.',
            C.DAMAGE_OUT)
        return

    # ── void walk / dark net — near-immunity (defense=50) for 8s ─────────────
    if canon == 'void_walk':
        expires = time.time() + 8.0
        world._buffs[nick] = {
            'attack':    0,
            'defense':   50,
            'dodge':     0,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('You step into the void — nearly untouchable for 8 seconds!',
                  bold=True, color=C.SAFE), C.SAFE)
        return

    # ── maelstrom / feedback loop — AoE damage + bleed on all ────────────────
    if canon == 'maelstrom':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'Nothing to maelstrom.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        base_dmg = random.randint(6, 10) + gl
        for npc in npcs_here:
            iid  = npc['instance_id']
            dmg  = max(1, base_dmg - npc.get('stats', {}).get('defense', 0) // 2)
            world.save_npc_instance(iid,
                current_blood=max(0, npc['current_blood'] - dmg))
            _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})['target'] = nick
            _npc_combat[iid].setdefault('hit_log', {})[nick] = (
                _npc_combat[iid]['hit_log'].get(nick, 0) + dmg)
            if npc.get('state') in ('idle', 'patrol'):
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=time.time() + 2.0)
            # Apply bleed DoT.
            world.add_status_effect(None, iid, 'bleed', max(1, gl // 2), 6, nick)
        msg(client, channel,
            spell_label + ': A maelstrom tears through %d enemies — '
            'all are bleeding!' % len(npcs_here), C.DAMAGE_OUT)
        for npc in npcs_here:
            fresh = _npc_fresh(world, npc['instance_id'])
            if fresh and fresh['current_blood'] <= 0:
                _npc_dies(world, channel, fresh, room_id)
        world.commit()
        return

    # ── divine intervention / emergency override — full heal + clear debuffs ──
    if canon == 'divine_intervention':
        world.update_player(nick, blood=player['max_blood'])
        world.db.execute(
            'DELETE FROM status_effects '
            'WHERE nick=? AND world=? AND effect IN ("bleed","burn","poison")',
            (nick, world.world_name))
        world._buffs.pop(nick, None)
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('FULL HEAL!', bold=True, color=C.HEAL) +
            ' All debuffs cleared.  (%d/%d blood)' % (
                player['max_blood'], player['max_blood']), C.HEAL)
        return

    # ── mind control / puppet master — turn NPC against its allies ───────────
    if canon == 'mind_control':
        npcs_here = world.get_npc_instances_in_room(room_id)
        target = next((n for n in npcs_here
                       if _npc_combat.get(n['instance_id'], {}).get('target') == nick),
                      npcs_here[0] if npcs_here else None)
        if target is None:
            msg(client, channel, 'No suitable target.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        iid     = target['instance_id']
        tier    = min(target.get('danger_tier', 1), 4)
        nl      = paint(target['name'], color=C.NPC[tier], bold=(tier >= 4))
        # Find another NPC in the room to redirect combat to.
        other = next((n for n in npcs_here if n['instance_id'] != iid), None)
        if other:
            _npc_combat[iid] = {'target': '__npc_%d' % other['instance_id'],
                                 'hit_log': {}}
            world.save_npc_instance(iid, next_action_at=time.time() + 1.0)
            other_nl = paint(other['name'],
                             color=C.NPC[min(other.get('danger_tier', 1), 4)])
            msg(client, channel,
                spell_label + ': ' + nl + ' turns on ' + other_nl + '!',
                C.DAMAGE_OUT)
        else:
            # No other NPC — just stun for a long time.
            world.save_npc_instance(iid, next_action_at=time.time() + 12.0)
            _npc_combat.pop(iid, None)
            msg(client, channel,
                spell_label + ': ' + nl +
                ' is mind-controlled and stands idle!', C.DAMAGE_OUT)
        world.commit()
        return

    # ── necromancy / reboot — drain the dead for a full heal ─────────────────
    if canon == 'necromancy':
        # Count dead NPC instances in this room.
        dead = world.db.execute(
            'SELECT i.instance_id FROM npc_instances i '
            'WHERE i.world=? AND i.room_id=? AND i.state="dead"',
            (world.world_name, room_id)
        ).fetchall()
        if not dead:
            msg(client, channel,
                'There are no dead to drain here.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        heal  = min(player['max_blood'] - player['blood'],
                    len(dead) * int(15 + gl * 2))
        new_b = player['blood'] + heal
        world.update_player(nick, blood=new_b)
        world.commit()
        msg(client, channel,
            spell_label + ': You drain %d corpse%s for ' % (
                len(dead), 's' if len(dead) != 1 else '') +
            paint('+%d blood' % heal, color=C.HEAL) +
            '  (%d/%d)' % (new_b, player['max_blood']), C.HEAL)
        return

    # ── singularity / kernel panic — instant wipe all NPCs (no XP/loot) ──────
    if canon == 'singularity':
        npcs_here = world.get_npc_instances_in_room(room_id)
        if not npcs_here:
            msg(client, channel, 'Nothing here to collapse.', C.SYSTEM)
            world.update_player(nick, stamina=stamina)
            world.commit()
            return
        now_t = time.time()
        for npc in npcs_here:
            iid   = npc['instance_id']
            delay = npc.get('respawn_delay') or 0
            if delay > 0:
                world.save_npc_instance(iid, state='dead', current_blood=0,
                                        respawn_at=now_t + delay,
                                        next_action_at=now_t + delay)
            else:
                world.save_npc_instance(iid, state='dead', current_blood=0,
                                        next_action_at=now_t + 86400.0)
            _npc_combat.pop(iid, None)
        world.commit()
        msg(client, channel,
            spell_label + ': Reality collapses. ' +
            paint(str(len(npcs_here)), bold=True) +
            ' enemies are annihilated.  ' +
            paint('(No XP or loot.)', color=C.SYSTEM), C.DAMAGE_OUT)
        return

    # ── apotheosis / godmode — all buffs maximised for 60s ───────────────────
    if canon == 'apotheosis':
        bonus   = int(10 + gl)
        expires = time.time() + 60.0
        world._buffs[nick] = {
            'attack':    bonus,
            'defense':   bonus,
            'dodge':     8,
            'expires_at': expires,
        }
        world.commit()
        msg(client, channel,
            spell_label + ': ' +
            paint('APOTHEOSIS!', bold=True, color=C.CRIT) +
            ' +%d attack, +%d defense, max dodge for 60 seconds.' % (bonus, bonus),
            C.CRIT)
        return

    # ── fallback for unknown abilities ────────────────────────────────────────
    msg(client, channel,
        spell_label + ' — not yet implemented.', C.SYSTEM)
    world.update_player(nick, stamina=stamina)  # refund
    world.commit()


def _cmd_use(client, channel, world, player, args):
    """use <item|spell> — consume a healing item or cast an ability."""
    nick    = client.nick
    t_name  = args.strip()

    if not t_name:
        msg(client, channel, 'Usage: use <item or spell name>', C.SYSTEM)
        return

    # ── Try consumable item first ─────────────────────────────────────────────
    item_row = world.db.execute(
        'SELECT inv.rowid, inv.quantity, i.item_id, i.name, i.item_type, i.stats '
        'FROM inventory inv JOIN items i ON inv.item_id = i.item_id '
        'WHERE inv.nick=? AND inv.world=? AND inv.on_corpse=0 '
        '  AND LOWER(i.name) LIKE ? AND i.item_type="consumable" '
        'LIMIT 1',
        (nick, world.world_name, '%' + t_name.lower() + '%')
    ).fetchone()

    if item_row:
        stats      = json.loads(item_row['stats'] or '{}')
        heal_amt   = stats.get('heal_amount', 0)
        stam_amt   = stats.get('stamina_amount', 0)
        clr_status = stats.get('clear_status', False)
        effects    = []

        if heal_amt:
            new_blood = min(player['blood'] + heal_amt, player['max_blood'])
            world.update_player(nick, blood=new_blood)
            effects.append(paint('+%d blood' % heal_amt, color=C.HEAL))
        if stam_amt:
            new_stam = min(player.get('stamina', 0) + stam_amt,
                           player.get('max_stamina', 10))
            world.update_player(nick, stamina=new_stam)
            effects.append(paint('+%d stamina' % stam_amt, color=C.SAFE))
        if clr_status:
            world.db.execute(
                'DELETE FROM status_effects '
                'WHERE nick=? AND world=? AND effect IN ("bleed","burn","poison")',
                (nick, world.world_name))
            effects.append(paint('status cleared', color=C.SAFE))

        if item_row['quantity'] > 1:
            world.db.execute(
                'UPDATE inventory SET quantity=quantity-1 WHERE rowid=?',
                (item_row['rowid'],))
        else:
            world.db.execute(
                'DELETE FROM inventory WHERE rowid=?', (item_row['rowid'],))
        world.commit()
        item_label = paint(item_row['name'], color=C.LOOT)
        if effects:
            msg(client, channel,
                'You use ' + item_label + ': ' + '  '.join(effects), C.HEAL)
        else:
            msg(client, channel, 'You use ' + item_label + '.', C.SYSTEM)
        return

    # ── Try spell/hack ────────────────────────────────────────────────────────
    spell_row = world.db.execute(
        'SELECT spell_name FROM spells '
        'WHERE nick=? AND world=? AND LOWER(spell_name) LIKE ?',
        (nick, world.world_name, '%' + t_name.lower() + '%')
    ).fetchone()

    if spell_row:
        _cast_spell(client, channel, world, player, spell_row['spell_name'])
        return

    msg(client, channel, "You don't have '%s'." % t_name, C.SYSTEM)


def _cmd_autofight(client, channel, world, player, args):
    """
    autofight — view or configure combat spell and style.
    Subcommands: spell <name>, spell none, style <tier>:<weight> [...].
    Healing → autoheal.  Looting → autoloot.  Autonomous play → autoplay.
    """
    nick = client.nick
    row  = world.db.execute(
        'SELECT * FROM autofight_profiles WHERE nick=? AND world=?',
        (nick, world.world_name)
    ).fetchone()

    if not row:
        world.db.execute(
            'INSERT OR IGNORE INTO autofight_profiles (nick, world) VALUES (?, ?)',
            (nick, world.world_name))
        world.commit()
        row = world.db.execute(
            'SELECT * FROM autofight_profiles WHERE nick=? AND world=?',
            (nick, world.world_name)
        ).fetchone()

    parts = args.strip().split(None, 2) if args.strip() else []
    sub   = parts[0].lower() if parts else ''

    if not sub or sub == 'show':
        style = json.loads(row['style_json'] or '{"cautious":10,"standard":60,"heavy":25,"reckless":5}')
        spell = row['spell_name'] or 'none (melee)'
        msg(client, channel, paint('Autofight profile:', bold=True), C.SYSTEM)
        msg(client, channel, '  spell: %s' % spell, C.SYSTEM)
        style_str = '  '.join('%s:%d' % (k, v) for k, v in style.items())
        msg(client, channel, '  style: ' + style_str, C.SYSTEM)
        return

    if sub == 'spell':
        spell_name = args.strip()[len('spell'):].strip() or 'none'
        if spell_name.lower() == 'none':
            world.db.execute(
                'UPDATE autofight_profiles SET spell_name=NULL '
                'WHERE nick=? AND world=?', (nick, world.world_name))
            world.commit()
            msg(client, channel, 'Autofight spell cleared (melee only).', C.SYSTEM)
        else:
            world.db.execute(
                'UPDATE autofight_profiles SET spell_name=? '
                'WHERE nick=? AND world=?', (spell_name, nick, world.world_name))
            world.commit()
            msg(client, channel,
                'Autofight spell set to ' +
                paint(spell_name, bold=True, color=C.SPELL) + '.', C.SYSTEM)
        return

    if sub == 'style':
        raw_style = args.strip()[len('style'):].strip()
        try:
            pairs   = dict(kv.split(':') for kv in raw_style.split())
            valid   = {'cautious', 'standard', 'heavy', 'reckless'}
            current = json.loads(row['style_json'] or
                                 '{"cautious":10,"standard":60,"heavy":25,"reckless":5}')
            for tier, val_s in pairs.items():
                tier = tier.lower()
                if tier not in valid:
                    raise ValueError(tier)
                val = int(val_s)
                if not 0 <= val <= 100:
                    raise ValueError(val)
                current = scale_autofight_style(current, tier, val)
            style_str = '  '.join('%s:%d' % (k, v) for k, v in current.items())
            msg(client, channel,
                'Autofight style updated: ' + style_str, C.SYSTEM)
            world.db.execute(
                'UPDATE autofight_profiles SET style_json=? '
                'WHERE nick=? AND world=?',
                (json.dumps(current), nick, world.world_name))
            world.commit()
        except Exception:
            msg(client, channel,
                'Usage: autofight style cautious:10 standard:60 heavy:25 reckless:5',
                C.SYSTEM)
        return

    msg(client, channel,
        'Usage: autofight [show | spell <name> | spell none | style <tier>:<weight> ...]  '
        '— see also: autoheal  autoloot  autoplay',
        C.SYSTEM)


# ---------------------------------------------------------------------------
# Stats / inventory / equip commands
# ---------------------------------------------------------------------------

def _cmd_stats(client, channel, world, player, args):
    """stats — show character sheet."""
    nick   = client.nick
    level  = player['level']
    guild  = player.get('guild') or 'None'
    gl     = _guild_level_for(world, nick, guild)
    xp     = player.get('xp', 0)
    needed = _xp_threshold(level, world.xp_factor)
    currency = 'credits' if world.base_game == 'cyberpunk' else 'gold'
    buf    = world._buffs.get(nick, {})
    buff_s = ''
    if buf and buf.get('expires_at', 0) > time.time():
        parts = []
        if buf.get('attack'):  parts.append('+%d ATK' % buf['attack'])
        if buf.get('defense'): parts.append('+%d DEF' % buf['defense'])
        if buf.get('dodge'):   parts.append('dodge+')
        if parts:
            buff_s = '  ' + paint('[Buffs: %s]' % ' '.join(parts), color=C.SAFE)
    w_dmg, w_name = _equipped_weapon(world, nick)
    karma   = float(player.get('karma', 0.0) or 0.0)
    if karma >= 10.0:
        karma_tag = paint('[Saintly]',   color=C.HEAL)
    elif karma >= 2.0:
        karma_tag = paint('[Good]',      color=C.SAFE)
    elif karma >= 0.5:
        karma_tag = paint('[Neutral+]',  color=C.SAFE)
    elif karma >= -0.5:
        karma_tag = paint('[Neutral]',   color=None)
    elif karma >= -2.0:
        karma_tag = paint('[Dubious]',   color=C.SYSTEM)
    elif karma >= -10.0:
        karma_tag = paint('[Wicked]',    color=C.DAMAGE_IN)
    else:
        karma_tag = paint('[Notorious]', color=C.DAMAGE_IN, bold=True)
    lines = [
        paint('── Character Sheet ──', bold=True),
        '  Nick: %s   Level: %d   Guild: %s (rank %d)   %s' % (
            nick, level, guild, gl, karma_tag),
        '  Blood: %d/%d   Stamina: %d/%d   %s: %d' % (
            player['blood'], player['max_blood'],
            player.get('stamina', 0), player.get('max_stamina', 10),
            currency, player.get('gold', 0)),
        '  XP: %d / %d   Weapon: %s (%d dmg)%s' % (xp, needed, w_name, w_dmg, buff_s),
    ]
    for line in lines:
        msg(client, channel, line, C.SYSTEM)

    # Active missions.
    missions = world.db.execute(
        'SELECT pq.quest_id, pq.progress, q.title, q.objective '
        'FROM player_quests pq '
        'JOIN quests q ON pq.quest_id=q.quest_id AND pq.world=q.world '
        "WHERE pq.nick=? AND pq.world=? AND pq.status='active'",
        (nick, world.world_name)
    ).fetchall()
    if missions:
        msg(client, channel, paint('── Active Missions ──', bold=True), C.SYSTEM)
        for m in missions:
            obj = json.loads(m['objective'])
            if obj.get('type') == 'kill':
                prog = '%d / %d %s killed' % (m['progress'], obj['count'], obj['npc_name'])
            else:
                prog = 'in progress'
            msg(client, channel,
                '  \u2022 ' + paint(m['title'], bold=True) + '  ' + prog, C.SYSTEM)


def _cmd_spells(client, channel, world, player, args):
    """spells — list known spells/hacks and their stamina costs."""
    nick  = client.nick
    label = 'hacks' if world.base_game == 'cyberpunk' else 'spells'
    rows  = world.db.execute(
        'SELECT spell_name, acquired_at FROM spells '
        'WHERE nick=? AND world=? ORDER BY acquired_at, spell_name',
        (nick, world.world_name)
    ).fetchall()
    if not rows:
        msg(client, channel, 'You know no %s yet.' % label, C.SYSTEM)
        return
    msg(client, channel, paint('── Known %s ──' % label.title(), bold=True), C.SYSTEM)
    for row in rows:
        canon, cost = _SPELL_CANON.get(row['spell_name'], (None, '?'))
        cost_str = ('  stamina: %s' % paint(str(cost), bold=True)) if cost != '?' else ''
        msg(client, channel,
            '  ' + paint(row['spell_name'], bold=True) + cost_str, C.SYSTEM)


def _cmd_inventory(client, channel, world, player, args):
    """inventory — list carried items."""
    nick = client.nick
    rows = world.db.execute(
        'SELECT inv.rowid, inv.quantity, inv.equipped, i.name, i.item_type '
        'FROM inventory inv JOIN items i ON inv.item_id = i.item_id '
        'WHERE inv.nick=? AND inv.world=? AND inv.on_corpse=0 '
        'ORDER BY inv.equipped DESC, i.name',
        (nick, world.world_name)
    ).fetchall()
    if not rows:
        msg(client, channel, 'Your inventory is empty.', C.SYSTEM)
        return
    msg(client, channel, paint('── Inventory ──', bold=True), C.SYSTEM)
    for r in rows:
        eq_tag = paint(' [equipped]', color=C.SAFE) if r['equipped'] else ''
        msg(client, channel,
            '  %s x%d (%s)%s' % (r['name'], r['quantity'], r['item_type'], eq_tag),
            C.SYSTEM)


def _cmd_equip(client, channel, world, player, args):
    """equip <item> — equip a weapon or armor from inventory."""
    nick   = client.nick
    t_name = args.strip().lower()
    if not t_name:
        msg(client, channel, 'Usage: equip <item name>', C.SYSTEM)
        return
    row = world.db.execute(
        'SELECT inv.rowid, i.name, i.item_type '
        'FROM inventory inv JOIN items i ON inv.item_id = i.item_id '
        'WHERE inv.nick=? AND inv.world=? AND inv.on_corpse=0 '
        '  AND LOWER(i.name) LIKE ? AND i.item_type IN ("weapon","armor")',
        (nick, world.world_name, '%' + t_name + '%')
    ).fetchone()
    if not row:
        msg(client, channel, "No equippable item matching '%s'." % args.strip(), C.SYSTEM)
        return
    # Unequip only the same slot type (weapon or armor) before equipping.
    world.db.execute(
        'UPDATE inventory SET equipped=0 '
        'WHERE nick=? AND world=? AND equipped=1 AND on_corpse=0 '
        '  AND item_id IN (SELECT item_id FROM items WHERE world=? AND item_type=?)',
        (nick, world.world_name, world.world_name, row['item_type']))
    world.db.execute(
        'UPDATE inventory SET equipped=1 WHERE rowid=?', (row['rowid'],))
    world.commit()
    msg(client, channel,
        'You equip ' + paint(row['name'], color=C.LOOT) + '.', C.SYSTEM)


def _cmd_unequip(client, channel, world, player, args):
    """unequip — remove currently equipped item."""
    nick = client.nick
    n = world.db.execute(
        'UPDATE inventory SET equipped=0 '
        'WHERE nick=? AND world=? AND equipped=1 AND on_corpse=0',
        (nick, world.world_name)).rowcount
    world.commit()
    if n:
        msg(client, channel, 'You stow your weapon/armor.', C.SYSTEM)
    else:
        msg(client, channel, 'Nothing equipped.', C.SYSTEM)


def _cmd_autoheal(client, channel, world, player, args):
    """autoheal — configure automatic healing during combat."""
    nick  = client.nick
    parts = args.strip().split(None, 1) if args.strip() else []
    sub   = parts[0].lower() if parts else ''
    rest  = parts[1].strip() if len(parts) > 1 else ''

    world.db.execute(
        'INSERT OR IGNORE INTO autofight_profiles (nick, world) VALUES (?, ?)',
        (nick, world.world_name))
    row = world.db.execute(
        'SELECT heal_threshold, heal_item FROM autofight_profiles WHERE nick=? AND world=?',
        (nick, world.world_name)
    ).fetchone()

    if not sub:
        if row and row['heal_threshold']:
            msg(client, channel,
                'Autoheal: heal below ' + paint('%d%%' % row['heal_threshold'], bold=True) +
                ' blood' +
                ((' using ' + paint(row['heal_item'], bold=True)) if row['heal_item'] else '') +
                '.  Type ' + paint('autoheal off', bold=True) + ' to disable.',
                C.SYSTEM)
        else:
            msg(client, channel,
                'Autoheal is ' + paint('off', color=C.SYSTEM) + '.  '
                'Example: ' + paint('autoheal 30', bold=True) +
                '  or  ' + paint('autoheal 40 potion', bold=True),
                C.SYSTEM)
        return

    if sub == 'off':
        world.db.execute(
            'UPDATE autofight_profiles SET heal_threshold=0, heal_item=NULL '
            'WHERE nick=? AND world=?', (nick, world.world_name))
        world.commit()
        msg(client, channel, 'Autoheal disabled.', C.SYSTEM)
        return

    try:
        pct       = int(sub)
        heal_item = rest or None
        assert 1 <= pct <= 100
        world.db.execute(
            'UPDATE autofight_profiles SET heal_threshold=?, heal_item=? '
            'WHERE nick=? AND world=?',
            (pct, heal_item, nick, world.world_name))
        world.commit()
        msg(client, channel,
            'Autoheal: heal below %d%% blood%s.' % (
                pct, (' using ' + heal_item) if heal_item else ''),
            C.SYSTEM)
    except (ValueError, AssertionError):
        msg(client, channel,
            'Usage: autoheal <1-100> [item_type]  |  autoheal off', C.SYSTEM)


def _cmd_autoloot(client, channel, world, player, args):
    """autoloot — toggle automatic corpse looting."""
    nick = client.nick
    sub  = args.strip().lower()

    world.db.execute(
        'INSERT OR IGNORE INTO autofight_profiles (nick, world) VALUES (?, ?)',
        (nick, world.world_name))
    row = world.db.execute(
        'SELECT autoloot FROM autofight_profiles WHERE nick=? AND world=?',
        (nick, world.world_name)
    ).fetchone()

    if not sub:
        on = bool(row and row['autoloot'])
        msg(client, channel,
            'Autoloot: ' + (paint('on', color=C.SAFE) if on
                            else paint('off', color=C.SYSTEM)) +
            '.  Type ' + paint('autoloot on', bold=True) +
            ' or ' + paint('autoloot off', bold=True) + ' to change.',
            C.SYSTEM)
        return

    if sub in ('on', 'off'):
        val = 1 if sub == 'on' else 0
        world.db.execute(
            'UPDATE autofight_profiles SET autoloot=? WHERE nick=? AND world=?',
            (val, nick, world.world_name))
        world.commit()
        msg(client, channel,
            'Autoloot ' + (paint('enabled', color=C.SAFE) if val
                           else paint('disabled', color=C.SYSTEM)) + '.',
            C.SYSTEM)
        return

    msg(client, channel, 'Usage: autoloot on|off', C.SYSTEM)


# ---------------------------------------------------------------------------
# Autoplay engine
# ---------------------------------------------------------------------------

_AUTOPLAY_MODES   = ('passive', 'defender', 'skirmisher', 'explorer', 'hunter', 'grinder')
_AUTOPLAY_INTERVAL = 8.0   # seconds between autonomous actions


def _autoplay_pick_exit(exits, came_from_id, visited_ids, style):
    """
    Choose an exit direction for autoplay movement.  Pure function — no world I/O.

    exits        — dict of {direction: dest_room_id}
    came_from_id — room_id we arrived from this session (or None)
    visited_ids  — set of room_ids already visited this session
    style        — 'explorer' or 'skirmisher'

    Explorer: all exits start equal; the exit back to came_from is weighted at
    0.25× (a quarter of its initial share); the freed probability is redistributed
    proportionally across the remaining exits.  ProbDist then picks one.

    Skirmisher: prefers exits leading to unvisited rooms (equal weight among
    unvisited); falls back to all exits if every neighbour has been visited.

    Returns (direction, dest_room_id) or (None, None).
    """
    if not exits:
        return None, None

    if style == 'explorer':
        weights = {d: (0.25 if rid == came_from_id else 1.0)
                   for d, rid in exits.items()}
        chosen = ProbDist(weights).pick
        return chosen, exits[chosen]

    # skirmisher — prefer unvisited
    unvisited = {d: rid for d, rid in exits.items() if rid not in visited_ids}
    pool      = unvisited if unvisited else exits
    chosen    = random.choice(list(pool.keys()))
    return chosen, pool[chosen]


def _autoplay_tick_player(world, channel, nick, player, now):
    """
    Run one autoplay action for a player.  Called from the director each tick
    when the player has an active autoplay_mode and enough time has elapsed.
    """
    last = _autoplay_last_act.get(nick, 0)
    if now - last < _AUTOPLAY_INTERVAL:
        return

    af = world.db.execute(
        'SELECT autoplay_mode, autoplay_target FROM autofight_profiles '
        'WHERE nick=? AND world=?',
        (nick, world.world_name)
    ).fetchone()
    if af is None or not af['autoplay_mode']:
        return

    mode    = af['autoplay_mode']
    room_id = player['room_id']
    state   = _autoplay_state.setdefault(nick, {'came_from': None, 'visited': set()})
    state['visited'].add(room_id)

    room    = world.get_room(room_id)
    exits   = (room.get('exits') or {}) if room else {}
    npcs    = world.get_npc_instances_in_room(room_id)
    hostiles = [n for n in npcs
                if n.get('behavior') in ('aggressive', 'aggressive_talker')
                and n.get('state') not in ('dead', 'respawning')]

    client_obj = next((c for c in channel.clients if c.nick == nick), None)
    if client_obj is None:
        return

    _autoplay_last_act[nick] = now

    if mode == 'passive':
        return  # autofight handles reactive combat; nothing proactive

    if mode == 'defender':
        if hostiles:
            t = hostiles[0]['name'].split()[0].lower()
            _cmd_attack(client_obj, channel, world, player, t)
        return

    if mode == 'skirmisher':
        if hostiles:
            t = hostiles[0]['name'].split()[0].lower()
            _cmd_attack(client_obj, channel, world, player, t)
            return
        direction, dest_id = _autoplay_pick_exit(
            exits, state['came_from'], state['visited'], 'skirmisher')
        if dest_id:
            state['came_from'] = room_id
            _cmd_go(client_obj, channel, world, player, direction)
        return

    if mode == 'explorer':
        if hostiles:
            _cmd_flee(client_obj, channel, world, player, '')
            return
        direction, dest_id = _autoplay_pick_exit(
            exits, state['came_from'], state['visited'], 'explorer')
        if dest_id:
            state['came_from'] = room_id
            _cmd_go(client_obj, channel, world, player, direction)
        return

    if mode in ('hunter', 'grinder'):
        target_filter = (af['autoplay_target'] or '').lower() if mode == 'grinder' else ''
        candidates = hostiles
        if not candidates:
            candidates = [n for n in npcs
                          if n.get('behavior') not in ('passive',)
                          and n.get('state') not in ('dead', 'respawning')]
        if target_filter:
            candidates = [n for n in candidates
                          if target_filter in n['name'].lower()]
        if candidates:
            t = candidates[0]['name'].split()[0].lower()
            _cmd_attack(client_obj, channel, world, player, t)
            return
        direction, dest_id = _autoplay_pick_exit(
            exits, state['came_from'], state['visited'], 'skirmisher')
        if dest_id:
            state['came_from'] = room_id
            _cmd_go(client_obj, channel, world, player, direction)
        return


_NPC_AUTOPLAY_INTERVAL = 12.0   # seconds between NPC autoplay actions


def _npc_can_autoplay(inst):
    """Return True if this NPC instance is eligible to use autoplay."""
    return (
        bool(inst.get('autoplay_mode')) and
        inst.get('danger_tier', 0) < 4 and
        inst.get('behavior', '') != 'aggressive_talker'
    )


def _npc_is_role(dialogue):
    """
    Return True if this NPC's dialogue dict marks it as a role NPC
    (vendor, mission-giver, or guild-change NPC) — these should not
    be given movement autoplay modes as they have a fixed spatial purpose.
    """
    topics = dialogue.get('topics', {}) if isinstance(dialogue, dict) else {}
    for v in topics.values():
        sv = str(v)
        if sv in ('__vendor__', '__guild_change__') or sv.startswith('__mission__'):
            return True
    return False


def _autoplay_tick_npc(world, channel, inst, now):
    """
    Run one autoplay tick for an NPC instance.  Called from the director's
    NPC autoplay loop when _npc_can_autoplay(inst) is True.

    Movement modes (explorer, skirmisher, hunter, grinder) use _autoplay_pick_exit.
    Combat for aggressive NPCs remains handled by the existing state machine.
    """
    iid  = inst['instance_id']
    if now - _autoplay_last_act.get(('npc', iid), 0) < _NPC_AUTOPLAY_INTERVAL:
        return

    mode    = inst['autoplay_mode']
    room_id = inst['room_id']
    state_s = inst.get('state', 'idle')

    # Combat is handled by the MarkovNet brain — don't interfere.
    if state_s == 'aggressive':
        return

    ap_state = _autoplay_state.setdefault(
        ('npc', iid), {'came_from': None, 'visited': set()})
    ap_state['visited'].add(room_id)

    room  = world.get_room(room_id)
    exits = (room.get('exits') or {}) if room else {}

    _autoplay_last_act[('npc', iid)] = now

    if mode == 'passive':
        # Stay put — suppress patrol movement without moving.
        world.save_npc_instance(iid, next_action_at=now + _NPC_AUTOPLAY_INTERVAL)
        return

    if mode == 'defender':
        # Engage players already in the room if aggressive; otherwise stand still.
        if inst.get('behavior') == 'aggressive':
            players = [p for p in world.players_in_room(room_id)
                       if p['nick'] in world._online
                       and not p.get('is_dead')
                       and not p.get('creation_state')]
            if players:
                target = random.choice(players)
                _npc_combat[iid] = {'target': target['nick'], 'hit_log': {}}
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=now + 2.0)
                tier      = min(inst.get('danger_tier', 1), 4)
                npc_label = paint(inst['name'], color=C.NPC[tier], bold=(tier >= 4))
                _msg_room(channel, world, room_id,
                          npc_label + ' snarls at ' +
                          paint(target['nick'], bold=True) + '!', C.DAMAGE_IN)
        return

    if mode in ('explorer', 'skirmisher'):
        pick_style = 'explorer' if mode == 'explorer' else 'skirmisher'
        direction, dest_id = _autoplay_pick_exit(
            exits, ap_state['came_from'], ap_state['visited'], pick_style)
        if dest_id:
            ap_state['came_from'] = room_id
            world.save_npc_instance(iid, room_id=dest_id,
                                    next_action_at=now + _NPC_AUTOPLAY_INTERVAL)
        return

    if mode in ('hunter', 'grinder'):
        target_filter = (inst.get('autoplay_target') or '').lower() \
                        if mode == 'grinder' else ''
        # If aggressive and players are here, engage.
        if inst.get('behavior') == 'aggressive':
            players = [p for p in world.players_in_room(room_id)
                       if p['nick'] in world._online
                       and not p.get('is_dead')
                       and not p.get('creation_state')
                       and (not target_filter or target_filter in p['nick'].lower())]
            if players:
                target = random.choice(players)
                _npc_combat[iid] = {'target': target['nick'], 'hit_log': {}}
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=now + 2.0)
                tier      = min(inst.get('danger_tier', 1), 4)
                npc_label = paint(inst['name'], color=C.NPC[tier], bold=(tier >= 4))
                _msg_room(channel, world, room_id,
                          npc_label + ' locks eyes on ' +
                          paint(target['nick'], bold=True) + '!', C.DAMAGE_IN)
                return
        # No target here — keep moving.
        direction, dest_id = _autoplay_pick_exit(
            exits, ap_state['came_from'], ap_state['visited'], 'skirmisher')
        if dest_id:
            ap_state['came_from'] = room_id
            world.save_npc_instance(iid, room_id=dest_id,
                                    next_action_at=now + _NPC_AUTOPLAY_INTERVAL)


def _cmd_autoplay(client, channel, world, player, args):
    """autoplay — configure autonomous character behaviour."""
    nick  = client.nick
    parts = args.strip().split(None, 1) if args.strip() else []
    sub   = parts[0].lower() if parts else ''
    rest  = parts[1].strip() if len(parts) > 1 else ''

    world.db.execute(
        'INSERT OR IGNORE INTO autofight_profiles (nick, world) VALUES (?, ?)',
        (nick, world.world_name))
    row = world.db.execute(
        'SELECT autoplay_mode, autoplay_respawn, autoplay_target '
        'FROM autofight_profiles WHERE nick=? AND world=?',
        (nick, world.world_name)
    ).fetchone()

    if not sub:
        mode    = row['autoplay_mode'] or 'off'
        respawn = bool(row['autoplay_respawn'])
        target  = row['autoplay_target'] or ''
        mode_c  = paint(mode, bold=True, color=C.SAFE if mode != 'off' else C.SYSTEM)
        resp_c  = paint('on', color=C.SAFE) if respawn else paint('off', color=C.SYSTEM)
        detail  = ('  target: ' + paint(target, bold=True)) if target else ''
        msg(client, channel,
            'Autoplay: %s  respawn: %s%s' % (mode_c, resp_c, detail), C.SYSTEM)
        if mode == 'off':
            msg(client, channel,
                '  Modes: ' + '  '.join(_AUTOPLAY_MODES), C.SYSTEM)
        return

    if sub == 'off':
        world.db.execute(
            'UPDATE autofight_profiles SET autoplay_mode=NULL, autoplay_target=NULL '
            'WHERE nick=? AND world=?', (nick, world.world_name))
        world.commit()
        _autoplay_state.pop(nick, None)
        _autoplay_last_act.pop(nick, None)
        msg(client, channel, 'Autoplay disabled.', C.SYSTEM)
        return

    if sub == 'respawn':
        val_s = rest.lower()
        if val_s in ('on', 'off'):
            val = 1 if val_s == 'on' else 0
            world.db.execute(
                'UPDATE autofight_profiles SET autoplay_respawn=? '
                'WHERE nick=? AND world=?', (val, nick, world.world_name))
            world.commit()
            msg(client, channel,
                'Autoplay will %s resume after respawn.' % (
                    paint('always', color=C.SAFE) if val
                    else paint('not', color=C.SYSTEM)),
                C.SYSTEM)
        else:
            msg(client, channel, 'Usage: autoplay respawn on|off', C.SYSTEM)
        return

    if sub in _AUTOPLAY_MODES:
        target_filter = rest if sub == 'grinder' else None
        world.db.execute(
            'UPDATE autofight_profiles SET autoplay_mode=?, autoplay_target=? '
            'WHERE nick=? AND world=?',
            (sub, target_filter, nick, world.world_name))
        world.commit()
        _autoplay_state.pop(nick, None)   # reset visited/came_from on mode change
        _autoplay_last_act.pop(nick, None)
        detail = (' — target filter: ' + paint(target_filter, bold=True)) if target_filter else ''
        msg(client, channel,
            'Autoplay: ' + paint(sub, bold=True, color=C.SAFE) + detail + '.', C.SYSTEM)
        return

    msg(client, channel,
        'Usage: autoplay [off | respawn on|off | %s]' % ' | '.join(_AUTOPLAY_MODES),
        C.SYSTEM)


# ---------------------------------------------------------------------------
# Command dispatch table
# ---------------------------------------------------------------------------

_COMMANDS = {
    'look':     _cmd_look,
    'l':        _cmd_look,
    'examine':  _cmd_look,
    'ex':       _cmd_look,
    'go':       _cmd_go,
    'say':      _cmd_say,
    'emote':    _cmd_emote,
    'me':       _cmd_emote,
    'who':      _cmd_who,
    'help':     _cmd_help,
    '?':        _cmd_help,
    'colors':   _cmd_colors,
    'colour':   _cmd_colors,
    'colours':  _cmd_colors,
    'follow':    _cmd_follow,
    'unfollow':  _cmd_unfollow,
    'party':     _cmd_party,
    'attack':    _cmd_attack,
    'a':         _cmd_attack,
    'flee':      _cmd_flee,
    'defend':    _cmd_defend,
    'd':         _cmd_defend,
    'use':       _cmd_use,
    'autofight': _cmd_autofight,
    'af':        _cmd_autofight,
    'autoheal':  _cmd_autoheal,
    'autoloot':  _cmd_autoloot,
    'autoplay':  _cmd_autoplay,
    'stats':     _cmd_stats,
    'score':     _cmd_stats,
    'inventory': _cmd_inventory,
    'inv':       _cmd_inventory,
    'i':         _cmd_inventory,
    'equip':     _cmd_equip,
    'unequip':   _cmd_unequip,
    'spells':    _cmd_spells,
    'hacks':     _cmd_spells,
    'abilities': _cmd_spells,
    'guild':     lambda c, ch, w, p, a: _guild_change_dialog_confirm(c, ch, w, p, a.strip()),
    'talk':      _cmd_talk,
    'ask':       _cmd_talk,
    'buy':       lambda c, ch, w, p, a: _cmd_talk(c, ch, w, p,
                     (a.split(None, 1)[0] if a else '') + ' buy ' +
                     (' '.join(a.split(None, 1)[1:]) if ' ' in a else '')),
    'sell':      lambda c, ch, w, p, a: _cmd_talk(c, ch, w, p,
                     (a.split(None, 1)[0] if a else '') + ' sell ' +
                     (' '.join(a.split(None, 1)[1:]) if ' ' in a else '')),
}


# ---------------------------------------------------------------------------
# PRIVMSG dispatcher
# ---------------------------------------------------------------------------

def _mud_dispatch(client, channel, world, ctx):
    """
    Parse the command from a PRIVMSG and route it to the appropriate handler.
    Called by MUD(ctx) for handle_privmsg events; ctx.cancel is set after
    this returns to suppress normal PRIVMSG fan-out.
    """
    nick = client.nick

    # Players not yet added to _online (banned, or joined before +MUD was set).
    if nick not in world._online:
        if world.is_banned(nick):
            msg(client, channel, 'You have been banned from this world.', C.SYSTEM)
        return

    player = world.get_player(nick)
    if player is None:
        return

    # ctx.params for handle_privmsg: '#channel :command text'
    raw = ctx.params
    if ' ' not in raw:
        return
    _, raw_text = raw.split(' ', 1)
    text = raw_text.lstrip(':').strip()
    if not text:
        return

    parts   = text.split(None, 1)
    command = parts[0].lower()
    args    = parts[1] if len(parts) > 1 else ''

    # Character creation wizard intercepts all input.
    if player.get('creation_state'):
        _wizard_dispatch(client, channel, world, player, text)
        return

    # Dead/observer state — all commands blocked.
    if player.get('is_dead'):
        msg(client, channel,
            'You hover over your body and look on in horror.', C.DEAD)
        return

    # Admin-frozen — block everything except look.
    if player.get('is_frozen') and command != 'look':
        msg(client, channel, 'You are frozen and cannot act.', C.SYSTEM)
        return

    # Admin command prefix.
    if command.startswith('@'):
        _cmd_admin(client, channel, world, player, command[1:], args)
        return

    # Direction shortcuts (bare compass words and abbreviations).
    full_dir = _DIR_FULL.get(command)
    if full_dir:
        _cmd_go(client, channel, world, player, full_dir)
        return
    if command in ('north', 'south', 'east', 'west', 'up', 'down'):
        _cmd_go(client, channel, world, player, command)
        return

    handler = _COMMANDS.get(command)
    if handler:
        if command in ('attack', 'a', 'flee', 'defend', 'd', 'use'):
            world._last_combat_action[nick] = time.time()
        handler(client, channel, world, player, args)
    else:
        msg(client, channel,
            "Unknown command '%s'. Type 'help' for a list of commands." % command,
            C.SYSTEM)


# ---------------------------------------------------------------------------
# AI director helpers
# ---------------------------------------------------------------------------

def _msg_room(channel, world, room_id, text, color=None):
    """Deliver text to every online player currently in room_id."""
    for client in list(channel.clients):
        if client.nick not in world._online:
            continue
        player = world.get_player(client.nick)
        if player and player.get('room_id') == room_id:
            msg(client, channel, text, color)


# ---------------------------------------------------------------------------
# Ollama NPC response
# ---------------------------------------------------------------------------

async def _probe_ollama_tps():
    """Silently measure tok/s on startup when model_enabled=1 is already in the DB."""
    global _ollama_tps
    if _ollama_client is None:
        return
    try:
        response = await _ollama_client.chat(
            model=MUD_MODEL,
            messages=[{'role': 'user', 'content': 'Hi.'}],
            options={'num_predict': 16},
        )
        eval_count    = response.get('eval_count', 0) or 1
        eval_duration = response.get('eval_duration', 1) or 1
        _ollama_tps = eval_count / (eval_duration / 1e9)
    except Exception:
        pass


async def _verify_and_enable_model(client, channel, world):
    """
    Send a minimal test prompt to MUD_MODEL.  On success, write model_enabled=1
    to the DB and report tokens/sec to the invoking user.  On failure, leave the
    DB unchanged, release the client if no other world needs it, and tell the user.
    """
    if _ollama_client is None:
        msg(client, channel,
            'ollama module is not installed — cannot enable model.', C.SYSTEM)
        return
    try:
        response = await _ollama_client.chat(
            model=MUD_MODEL,
            messages=[{'role': 'user', 'content': 'Hi.'}],
            options={'num_predict': 16},
        )
        eval_count    = response.get('eval_count', 0) or 1
        eval_duration = response.get('eval_duration', 1) or 1   # nanoseconds
        tps = eval_count / (eval_duration / 1e9)
    except Exception as e:
        msg(client, channel,
            'Model %s failed: %s' % (paint(MUD_MODEL, bold=True), str(e)[:120]),
            C.SYSTEM)
        _release_ollama_client_if_unused(client.server)
        return

    global _ollama_tps
    _ollama_tps = tps

    world.db.execute(
        'UPDATE worlds SET model_enabled=1 WHERE world_name=?',
        (world.world_name,)
    )
    world.db.commit()
    msg(client, channel,
        'NPC AI model %s on.  (%.1f tok/s)' % (
            paint(MUD_MODEL, bold=True), tps),
        C.SYSTEM)


async def _ollama_npc_response(client, channel, world, player, npc, room, speech):
    """
    Generate an NPC response via ollama and deliver it room-scoped.
    Each line is prefixed with '▫ ' to mark it as model-generated.
    Fires as a background task so _cmd_talk never blocks.
    """
    if _ollama_client is None:
        return

    npc_name  = npc['name']
    npc_desc  = npc.get('description') or 'a figure'
    room_id   = player['room_id']
    tier      = min(npc.get('danger_tier', 0), len(C.NPC) - 1)
    npc_label = paint(npc_name, color=C.NPC[tier])

    # Other players present
    others = [
        c.nick for c in channel.clients
        if c.nick != client.nick
        and c.nick in world._online
        and (lambda p: p and p.get('room_id') == room_id)(world.get_player(c.nick))
    ]

    # NPC inventory from loot template
    loot = npc.get('loot') or []
    inv_desc = (', '.join(str(i) for i in loot[:6])) if loot else 'nothing notable'

    p_level = player.get('level', 1)
    p_guild = player.get('guild') or 'no guild'

    # Pull dialogue context: greeting and topic keys (not values, to keep prompt short)
    npc_dialogue = npc.get('dialogue') or {}
    greeting = npc_dialogue.get('greeting', '')
    topic_keys = [k for k, v in npc_dialogue.get('topics', {}).items()
                  if not str(v).startswith('__')]   # skip special directives

    system = (
        'You are %s. %s '
        'You are in %s: %s '
        '%s'
        'You are carrying: %s. '
        '%s'
        '%s'
        'You are in an IRC MUD text game. '
        'Never use markdown, asterisks, or any special formatting. Plain text only. '
        'Keep each line of your response under 200 characters. '
        'Use as few lines as possible; never exceed 5 lines total.'
    ) % (
        npc_name, npc_desc,
        room['name'], (room.get('description') or '').strip(),
        ('Others present: %s. ' % ', '.join(others)) if others else '',
        inv_desc,
        ('Your usual greeting: "%s" ' % greeting) if greeting else '',
        ('You have scripted knowledge on: %s. Stay consistent with this. '
         % ', '.join(topic_keys)) if topic_keys else '',
    )

    user_line = '%s (level %d %s) says: %s' % (client.nick, p_level, p_guild, speech)

    try:
        import ollama as _ol
        response = await _ollama_client.chat(
            model=MUD_MODEL,
            messages=[
                {'role': 'system', 'content': system},
                {'role': 'user',   'content': user_line},
            ],
            options={'num_predict': 200},
        )
        raw = response['message']['content'].strip()
    except Exception:
        return

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()][:5]
    for line in lines:
        _msg_room(channel, world, room_id,
                  npc_label + ' says: ▫ ' + paint(line[:200], color=C.NPC[tier]))


# ---------------------------------------------------------------------------
# AI director
# ---------------------------------------------------------------------------

async def _director(world, channel, server):
    """
    One asyncio.Task per world.  Runs a 1-second tick loop that drives:
      • NPC state machine (idle / patrol / aggressive / fleeing / dead)
      • Passive player regen (blood and stamina)
      • Dead-player respawn countdown
      • Status-effect tick-down and on-tick damage
      • Per-room tension drift
      • Periodic sqlite flush (every 5 s)

    Cancels itself if the channel is removed from the server.
    """
    FLUSH_INTERVAL = 5.0
    last_flush     = time.time()

    while True:
        await asyncio.sleep(1.0)
        try:
            now = time.time()

            # ── Guard: cancel if channel is gone ────────────────────────────
            if channel.name not in server.channels:
                _directors.pop(world.world_name, None)
                return

            # ── NPC state machine ────────────────────────────────────────────
            for inst in world.get_tickable_instances():
                _director_tick_npc(world, channel, inst, now)

            # ── NPC autoplay ──────────────────────────────────────────────────
            for inst in world.get_autoplayable_instances():
                _autoplay_tick_npc(world, channel, inst, now)

            # ── Player regen and respawn ─────────────────────────────────────
            for nick in list(world._online):
                player = world.get_player(nick)
                if player is None:
                    continue

                if player.get('is_dead'):
                    # Respawn countdown.
                    respawn_at = player.get('respawn_at')
                    if respawn_at and now >= float(respawn_at):
                        world_rec = world.get_world()
                        safe_room = (player.get('last_safe_room_id')
                                     or world_rec['start_room_id'])
                        world.update_player(nick,
                                            is_dead=0, blood=1,
                                            room_id=safe_room,
                                            respawn_at=None,
                                            last_regen_at=now)
                        # Decay unclaimed corpse items.
                        world.db.execute(
                            'DELETE FROM inventory WHERE nick=? AND world=? AND on_corpse=1',
                            (nick, world.world_name)
                        )
                        # Reset autoplay session state; disable mode if respawn=off.
                        _autoplay_state.pop(nick, None)
                        _autoplay_last_act.pop(nick, None)
                        af_r = world.db.execute(
                            'SELECT autoplay_respawn FROM autofight_profiles '
                            'WHERE nick=? AND world=?',
                            (nick, world.world_name)
                        ).fetchone()
                        if af_r and not af_r['autoplay_respawn']:
                            world.db.execute(
                                'UPDATE autofight_profiles SET autoplay_mode=NULL '
                                'WHERE nick=? AND world=?',
                                (nick, world.world_name)
                            )
                        client_obj = next(
                            (c for c in channel.clients if c.nick == nick), None)
                        if client_obj:
                            msg(client_obj, channel,
                                paint('You return from the void.', bold=True), C.SAFE)
                            _show_room(client_obj, channel, world, safe_room)
                    continue

                # Passive regen — skip players mid-creation.
                if player.get('creation_state'):
                    continue

                last_regen = float(player.get('last_regen_at') or now)
                elapsed    = now - last_regen
                regen_int  = max(2, 30 - player['level'] // 5)  # stamina interval
                b_gain     = int(elapsed / 120.0)               # 1 blood per 120 s
                s_gain     = int(elapsed / regen_int)

                if b_gain > 0 or s_gain > 0:
                    new_blood   = min(player['blood']   + b_gain,  player['max_blood'])
                    new_stamina = min(player['stamina'] + s_gain,  player['max_stamina'])
                    world.update_player(nick, blood=new_blood,
                                        stamina=new_stamina, last_regen_at=now)

            # ── Status-effect tick-down ──────────────────────────────────────
            for row in world.db.execute(
                    'SELECT * FROM status_effects WHERE world=?',
                    (world.world_name,)).fetchall():
                remaining = row['ticks_remaining'] - 1
                if remaining <= 0:
                    world.db.execute(
                        'DELETE FROM status_effects WHERE id=?', (row['id'],))
                else:
                    world.db.execute(
                        'UPDATE status_effects SET ticks_remaining=? WHERE id=?',
                        (remaining, row['id']))
                    effect = row['effect']
                    if effect in ('bleed', 'burn', 'poison'):
                        sev  = row['severity'] or 1
                        n    = row['nick']
                        if n and n in world._online:
                            p = world.get_player(n)
                            if p and not p.get('is_dead'):
                                world.update_player(n,
                                    blood=max(0, p['blood'] - sev))
                                target_c = next(
                                    (c for c in channel.clients if c.nick == n), None)
                                if target_c:
                                    msg(target_c, channel,
                                        paint('[%s] You take %d damage.'
                                              % (effect.title(), sev),
                                              color=C.DAMAGE_IN))
                    elif effect == 'regen':
                        sev = row['severity'] or 1
                        n   = row['nick']
                        if n and n in world._online:
                            p = world.get_player(n)
                            if p and not p.get('is_dead'):
                                nb = min(p['blood'] + sev, p['max_blood'])
                                world.update_player(n, blood=nb)
                                target_c = next(
                                    (c for c in channel.clients if c.nick == n), None)
                                if target_c:
                                    msg(target_c, channel,
                                        paint('[Regen] +%d blood' % sev,
                                              color=C.HEAL))
                    elif effect == 'poison' and row['instance_id']:
                        # Poison on an NPC instance.
                        sev = row['severity'] or 1
                        iid = row['instance_id']
                        ni  = world.db.execute(
                            'SELECT i.*, n.stats FROM npc_instances i '
                            'JOIN npcs n ON i.npc_id=n.npc_id '
                            'WHERE i.instance_id=?', (iid,)).fetchone()
                        if ni and ni['state'] not in ('dead',):
                            nb = max(0, ni['current_blood'] - sev)
                            world.save_npc_instance(iid, current_blood=nb)
                            src = row['source']
                            src_client = next(
                                (c for c in channel.clients if c.nick == src), None)
                            if src_client:
                                msg(src_client, channel,
                                    paint('[Poison] ', color=C.DAMAGE_OUT) +
                                    ni['name'] + ' takes %d.' % sev)
                            if nb <= 0:
                                d = dict(ni)
                                d['stats'] = json.loads(d['stats'] or '{}')
                                world.db.execute(
                                    'DELETE FROM status_effects WHERE id=?',
                                    (row['id'],))
                                _npc_dies(world, channel, d, d['room_id'])

            # ── Tension drift ────────────────────────────────────────────────
            for room_id, tension in list(world._tension.items()):
                if tension > 0.0:
                    world.set_tension(room_id, tension - 0.005)  # ~3.5 min decay

            # ── Lingering player cleanup ──────────────────────────────────────
            online_nicks = {c.nick for c in channel.clients}
            for nick in list(world._online):
                if nick not in online_nicks:
                    # Player disconnected without a PART event (killed connection,
                    # QUIT without cmode firing, etc.).  Give a 10-second grace.
                    expire = world._lingering.get(nick)
                    if expire is None:
                        world._lingering[nick] = now + 10.0
                    elif now >= expire:
                        world._lingering.pop(nick, None)
                        world._online.discard(nick)
                        world._defending.discard(nick)
                        world._last_combat_action.pop(nick, None)
                        world._buffs.pop(nick, None)
                        _autoplay_state.pop(nick, None)
                        _autoplay_last_act.pop(nick, None)
                        # Clear any NPC targeting this nick.
                        for iid, combat in list(_npc_combat.items()):
                            if combat.get('target') == nick:
                                _npc_combat.pop(iid, None)
                else:
                    # Player is still present — clear any lingering timer.
                    world._lingering.pop(nick, None)

            # ── Expire stale buffs ────────────────────────────────────────────
            for bn in list(world._buffs):
                if world._buffs[bn].get('expires_at', 0) <= now:
                    world._buffs.pop(bn, None)

            # ── Autofight ─────────────────────────────────────────────────────
            AF_IDLE = 5.0   # seconds of combat silence before autofight fires
            for nick in list(world._online):
                last_act = world._last_combat_action.get(nick, 0)
                if now - last_act < AF_IDLE:
                    continue
                player = world.get_player(nick)
                if player is None or player.get('is_dead') or player.get('creation_state'):
                    continue
                room_id = player['room_id']
                # Check if any NPC is targeting this player aggressively.
                hostile = [inst for inst in world.get_npc_instances_in_room(room_id)
                           if _npc_combat.get(inst['instance_id'], {}).get('target') == nick
                           and inst.get('state') == 'aggressive']
                if not hostile:
                    continue
                # Load autofight profile.
                af_row = world.db.execute(
                    'SELECT * FROM autofight_profiles WHERE nick=? AND world=?',
                    (nick, world.world_name)
                ).fetchone()
                if af_row is None:
                    continue  # autofight not configured

                client_obj = next(
                    (c for c in channel.clients if c.nick == nick), None)
                if client_obj is None:
                    continue

                world._last_combat_action[nick] = now

                # Autoheal if below threshold and have consumables.
                heal_thr = af_row['heal_threshold'] or 0
                if heal_thr and player['max_blood'] > 0:
                    pct = int(player['blood'] * 100 / player['max_blood'])
                    if pct <= heal_thr:
                        heal_item = af_row['heal_item'] or ''
                        item_q = (
                            'SELECT inv.rowid, inv.quantity, i.name, i.stats '
                            'FROM inventory inv JOIN items i ON inv.item_id=i.item_id '
                            'WHERE inv.nick=? AND inv.world=? AND inv.on_corpse=0 '
                            '  AND i.item_type="consumable"'
                        )
                        params = [nick, world.world_name]
                        if heal_item:
                            item_q += ' AND LOWER(i.name) LIKE ?'
                            params.append('%' + heal_item.lower() + '%')
                        item_q += ' LIMIT 1'
                        ir = world.db.execute(item_q, params).fetchone()
                        if ir:
                            st = json.loads(ir['stats'] or '{}')
                            ha = st.get('heal_amount', 0)
                            if ha:
                                new_b = min(player['blood'] + ha, player['max_blood'])
                                world.update_player(nick, blood=new_b)
                                if ir['quantity'] > 1:
                                    world.db.execute(
                                        'UPDATE inventory SET quantity=quantity-1 '
                                        'WHERE rowid=?', (ir['rowid'],))
                                else:
                                    world.db.execute(
                                        'DELETE FROM inventory WHERE rowid=?',
                                        (ir['rowid'],))
                                msg(client_obj, channel,
                                    paint('[AF] Auto-healed with ', color=C.HEAL) +
                                    paint(ir['name'], color=C.LOOT) +
                                    paint(' (+%d blood)' % ha, color=C.HEAL))
                                player = world.get_player(nick)  # refresh

                # Auto-cast spell if configured and player alive.
                af_spell = af_row['spell_name']
                if af_spell and player and not player.get('is_dead'):
                    _cast_spell(client_obj, channel, world, player, af_spell)
                    continue

                # Default: melee attack on primary hostile.
                npc_target = hostile[0]
                t_name_af  = npc_target['name'].split()[0].lower()
                # Re-read player to get up-to-date stamina/blood.
                player = world.get_player(nick)
                if player and not player.get('is_dead'):
                    _cmd_attack(client_obj, channel, world, player, t_name_af)

            # ── Autoplay ──────────────────────────────────────────────────────
            for nick in list(world._online):
                player = world.get_player(nick)
                if player is None or player.get('is_dead') or player.get('creation_state'):
                    continue
                _autoplay_tick_player(world, channel, nick, player, now)

            # ── Periodic flush ───────────────────────────────────────────────
            if now - last_flush >= FLUSH_INTERVAL:
                world.commit()
                last_flush = now

        except asyncio.CancelledError:
            raise
        except Exception:
            pass  # Never let the director die on a transient error.


def _build_npc_brain(tier):
    """
    Build a fresh MarkovNet combat brain for an NPC of the given danger_tier (0–4).

    Five action nodes: attack, heavy_hit, flee, taunt, defend. Weighted transitions
    encode the NPC's tactical personality:
      - After heavy_hit: weight shifts toward pressing the attack.
      - flee is low-probability by default; boosted reactively when blood < 25%.
      - After casting taunt: higher chance of a follow-up heavy blow.
      - defend leads back into attack/heavy sequences.

    Boss-tier NPCs (tier 4) use _BossAction (gain=0.4) so powerful moves chain
    more aggressively. Trivial NPCs (tier 0) use _WeakAction (gain=-0.3).

    The brain is instantiated when the NPC first attacks and stored in _npc_brains
    keyed on instance_id. It is discarded (_npc_brains.pop) when combat resolves.
    No sqlite serialisation is needed; a server restart gives the NPC a fresh brain.
    """
    FuncCls = _BossAction if tier >= 4 else (_WeakAction if tier == 0 else Func)

    def do_attack(world, channel, inst, target_p, now):
        iid   = inst['instance_id']
        stats = inst.get('stats', {})
        t     = min(inst.get('danger_tier', 1), 4)
        label = paint(inst['name'], color=C.NPC[t], bold=(t >= 4))
        nick  = target_p['nick']
        party_size = len(_npc_combat.get(iid, {}).get('hit_log', {}))
        scale = 1.0 + 0.25 * max(0, party_size - 1)
        base  = max(1, stats.get('attack', 2) + random.randint(1, 6))
        dmg   = max(0, int(base * scale) - _player_defense(world, nick))
        new_b = max(0, target_p['blood'] - dmg)
        world.update_player(nick, blood=new_b)
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})
        _npc_combat[iid]['hit_log'][nick] = _npc_combat[iid]['hit_log'].get(nick, 0) + dmg
        _msg_room(channel, world, inst['room_id'],
            label + ' strikes ' + paint(nick, bold=True) +
            ' for ' + paint(str(dmg), color=C.DAMAGE_IN) + ' damage.', C.DAMAGE_IN)
        return 'player_dead' if new_b <= 0 else 'attack'

    def do_heavy_hit(world, channel, inst, target_p, now):
        iid   = inst['instance_id']
        stats = inst.get('stats', {})
        t     = min(inst.get('danger_tier', 1), 4)
        label = paint(inst['name'], color=C.NPC[t], bold=(t >= 4))
        nick  = target_p['nick']
        party_size = len(_npc_combat.get(iid, {}).get('hit_log', {}))
        scale = 1.0 + 0.25 * max(0, party_size - 1)
        base  = max(1, stats.get('attack', 2) + random.randint(1, 6))
        dmg   = max(0, int(base * 1.5 * scale) - _player_defense(world, nick))
        new_b = max(0, target_p['blood'] - dmg)
        world.update_player(nick, blood=new_b)
        _npc_combat.setdefault(iid, {'target': nick, 'hit_log': {}})
        _npc_combat[iid]['hit_log'][nick] = _npc_combat[iid]['hit_log'].get(nick, 0) + dmg
        _msg_room(channel, world, inst['room_id'],
            label + paint(' lands a crushing blow', bold=True) + ' on ' +
            paint(nick, bold=True) +
            ' for ' + paint(str(dmg), color=C.DAMAGE_IN) + ' damage!', C.DAMAGE_IN)
        return 'player_dead' if new_b <= 0 else 'heavy_hit'

    def do_flee(world, channel, inst, target_p, now):
        t     = min(inst.get('danger_tier', 1), 4)
        label = paint(inst['name'], color=C.NPC[t], bold=(t >= 4))
        _msg_room(channel, world, inst['room_id'],
            label + ' breaks away and flees!', C.DAMAGE_OUT)
        return 'flee'

    def do_taunt(world, channel, inst, target_p, now):
        t     = min(inst.get('danger_tier', 1), 4)
        label = paint(inst['name'], color=C.NPC[t], bold=(t >= 4))
        _msg_room(channel, world, inst['room_id'],
            label + ' taunts ' + paint(target_p['nick'], bold=True) +
            ', daring them to attack!', C.NARRATION)
        return 'taunt'

    def do_defend(world, channel, inst, target_p, now):
        t     = min(inst.get('danger_tier', 1), 4)
        label = paint(inst['name'], color=C.NPC[t], bold=(t >= 4))
        _msg_room(channel, world, inst['room_id'],
            label + ' braces into a defensive stance.', C.NARRATION)
        return 'defend'

    attack    = FuncCls(do_attack,    P=1.0)
    heavy_hit = FuncCls(do_heavy_hit, P=0.5)
    flee      = FuncCls(do_flee,      P=0.3)
    taunt     = FuncCls(do_taunt,     P=0.4)
    defend    = FuncCls(do_defend,    P=0.5)

    attack.update(   {heavy_hit: 30, attack: 50, taunt: 10, defend: 10})
    heavy_hit.update({attack:    60, heavy_hit: 20, flee: 20})
    flee.update(     {flee:      80, attack: 20})
    taunt.update(    {attack:    50, heavy_hit: 20, defend: 30})
    defend.update(   {attack:    60, heavy_hit: 20, taunt: 20})

    return MarkovNet(attack, heavy_hit, flee, taunt, defend)


def _director_tick_npc(world, channel, inst, now):
    """
    Process one NPC instance through the state machine for the current tick.
    Mutates sqlite state via world.save_npc_instance / world.update_player.
    """
    iid      = inst['instance_id']
    state    = inst.get('state', 'idle')
    room     = inst['room_id']
    stats    = inst.get('stats', {})
    behavior = inst.get('behavior', 'idle')
    tier     = min(inst.get('danger_tier', 1), 4)
    npc_label = paint(inst['name'], color=C.NPC[tier], bold=(tier >= 4))

    # ── dead / respawning ────────────────────────────────────────────────────
    if state == 'dead':
        respawn_at = inst.get('respawn_at')
        if respawn_at and now >= float(respawn_at):
            world.save_npc_instance(iid,
                room_id=inst['spawn_room_id'],
                current_blood=stats.get('max_blood', 10),
                state='idle',
                next_action_at=now + 2.0,
                respawn_at=None)
        else:
            world.save_npc_instance(iid, next_action_at=now + 5.0)
        return

    # ── idle ─────────────────────────────────────────────────────────────────
    if state == 'idle':
        if inst.get('autoplay_mode') and _npc_can_autoplay(inst):
            # Autoplay owns movement — just advance the tick timer.
            world.save_npc_instance(iid, next_action_at=now + _NPC_AUTOPLAY_INTERVAL)
            return
        if behavior == 'aggressive':
            targets = [p for p in world.players_in_room(room)
                       if p['nick'] in world._online
                       and not p.get('is_dead')
                       and not p.get('creation_state')]
            if targets:
                target = random.choice(targets)
                _npc_combat[iid] = {'target': target['nick'], 'hit_log': {}}
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=now + 2.0)
                _msg_room(channel, world, room,
                    npc_label + ' snarls at ' +
                    paint(target['nick'], bold=True) + '!', C.DAMAGE_IN)
                return
        if behavior == 'patrol':
            world.save_npc_instance(iid, state='patrol', next_action_at=now + 3.0)
            return
        world.save_npc_instance(iid, next_action_at=now + 5.0)
        return

    # ── patrol ───────────────────────────────────────────────────────────────
    if state == 'patrol':
        if inst.get('autoplay_mode') and _npc_can_autoplay(inst):
            world.save_npc_instance(iid, next_action_at=now + _NPC_AUTOPLAY_INTERVAL)
            return
        # Aggressive patrollers attack on sight.
        if behavior == 'aggressive':
            targets = [p for p in world.players_in_room(room)
                       if p['nick'] in world._online
                       and not p.get('is_dead')
                       and not p.get('creation_state')]
            if targets:
                target = random.choice(targets)
                _npc_combat[iid] = {'target': target['nick'], 'hit_log': {}}
                world.save_npc_instance(iid, state='aggressive',
                                        next_action_at=now + 2.0)
                _msg_room(channel, world, room,
                    npc_label + ' spots ' + paint(target['nick'], bold=True) + '!',
                    C.DAMAGE_IN)
                return
        rm    = world.get_room(room)
        exits = rm.get('exits', {}) if rm else {}
        if exits:
            dest = random.choice(list(exits.values()))
            world.save_npc_instance(iid, room_id=dest, next_action_at=now + 5.0)
        else:
            world.save_npc_instance(iid, state='idle', next_action_at=now + 5.0)
        return

    # ── aggressive ───────────────────────────────────────────────────────────
    if state == 'aggressive':
        combat = _npc_combat.get(iid)
        if not combat:
            _npc_brains.pop(iid, None)
            world.save_npc_instance(iid, state='idle', next_action_at=now + 2.0)
            return
        target_nick = combat['target']
        target_p    = world.get_player(target_nick)
        if (target_p is None
                or target_p.get('room_id') != room
                or target_p.get('is_dead')
                or target_nick not in world._online):
            _npc_combat.pop(iid, None)
            _npc_brains.pop(iid, None)
            world.save_npc_instance(iid, state='idle', next_action_at=now + 2.0)
            return

        # Get or build the per-instance MarkovNet combat brain.
        brain = _npc_brains.get(iid)
        if brain is None:
            brain = _build_npc_brain(tier)
            _npc_brains[iid] = brain

        # Reactive probability shift: boost flee weight as NPC blood drops below 25%.
        max_b     = stats.get('max_blood', 10)
        blood_pct = inst['current_blood'] / max(1, max_b)
        for node in brain:
            fname = getattr(getattr(node, 'func', None), '__name__', '')
            if fname == 'do_flee':
                node.P = 0.8 if blood_pct <= 0.25 else 0.3
            elif fname == 'do_attack':
                node.P = 0.5 if blood_pct <= 0.25 else 1.0

        # Execute one action via the Markov chain; returns a status string.
        result = brain(world, channel, inst, target_p, now)

        if result == 'flee':
            _npc_combat.pop(iid, None)
            _npc_brains.pop(iid, None)
            world.save_npc_instance(iid, state='fleeing', next_action_at=now + 1.0)
            return

        speed = stats.get('attack_speed', 3.0)
        if result == 'player_dead':
            delay = max(1.0, 10.0 / max(1, target_p['level']))
            world.update_player(target_nick, is_dead=1, blood=0,
                                respawn_at=now + delay)
            _npc_combat.pop(iid, None)
            _npc_brains.pop(iid, None)
            world.save_npc_instance(iid, state='idle', next_action_at=now + 2.0)
            _msg_room(channel, world, room,
                paint(target_nick, bold=True) + ' has been slain by ' +
                npc_label + '!', C.DEAD)
            target_client = next(
                (c for c in channel.clients if c.nick == target_nick), None)
            if target_client:
                msg(target_client, channel,
                    paint('You are dead.', bold=True) +
                    ' You will respawn in %d seconds.' % int(delay), C.DEAD)
            corpse_items = _mark_player_corpse(world, target_nick)
            if corpse_items:
                _do_autoloot(world, channel, room, corpse_items,
                             paint(target_nick, bold=True) + "'s corpse",
                             corpse_nick=target_nick)
            return

        world.save_npc_instance(iid, next_action_at=now + speed)
        return

    # ── fleeing ──────────────────────────────────────────────────────────────
    if state == 'fleeing':
        _npc_combat.pop(iid, None)
        rm    = world.get_room(room)
        exits = rm.get('exits', {}) if rm else {}
        if exits:
            dest = random.choice(list(exits.values()))
            world.save_npc_instance(iid, room_id=dest, next_action_at=now + 3.0)
        else:
            world.save_npc_instance(iid, state='idle', next_action_at=now + 3.0)
        return

    # ── unknown state — reset ────────────────────────────────────────────────
    world.save_npc_instance(iid, state='idle', next_action_at=now + 2.0)


_build_help_topics()

# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

__package__ = [{"name": "mud", "type": "cmode",
                "description": "Transforms a channel into a persistent multi-user dungeon."}]


def MUD(ctx):
    """
    cmode callable — invoked by the @scripts decorator on every IRC command
    targeting a channel where +MUD is set.

    Intercept map:
      handle_join     → _mud_join()     (do not cancel — IRC join must complete)
      handle_part     → _mud_part()     (do not cancel — IRC part must complete)
      handle_privmsg  → _mud_dispatch() then ctx.cancel = True (suppress echo)
      everything else → pass through unchanged

    The World object is created lazily on the first call for a given channel
    and cached in the module-level _worlds dict and on server.mud_worlds.
    """
    # New-channel notification from handle_join (no func in ctx).
    if ctx.get('new'):
        return

    func = ctx.get('func')
    if func is None:
        return
    func_name = func.__name__

    client  = ctx.client
    channel = ctx.channel

    world = _get_or_init_world(channel, client.server)
    if world is None:
        return

    # Start the AI director task if not already running for this world.
    if world.world_name not in _directors:
        try:
            loop = asyncio.get_event_loop()
            task = loop.create_task(_director(world, channel, client.server))
            _directors[world.world_name] = task
            if hasattr(client.server, 'mud_directors'):
                client.server.mud_directors[world.world_name] = task
        except RuntimeError:
            pass  # No running event loop (e.g. unit tests).

        # First activation: call _mud_join for every client already in the
        # channel (they won't get a handle_join since they were here before
        # +mud was set).
        for c in list(channel.clients):
            _mud_join(c, channel, world)
        return

    if func_name == 'handle_join':
        _mud_join(client, channel, world)
        return   # do NOT cancel — normal IRC JOIN (NAMES etc.) must complete

    if func_name == 'handle_part':
        _mud_part(client, channel, world)
        return   # do NOT cancel — normal IRC PART must complete

    if func_name == 'handle_privmsg':
        _mud_dispatch(client, channel, world, ctx)
        ctx.cancel = True   # suppress normal PRIVMSG fan-out
        return


def __init__(ctx):
    global _srv_domain
    _srv_domain = ctx.server.config.server.domain
    if not hasattr(ctx.server, 'mud_directors'):
        ctx.server.mud_directors = _directors
    if not hasattr(ctx.server, 'mud_worlds'):
        ctx.server.mud_worlds = _worlds
    if not hasattr(ctx.server, 'mud_db'):
        db_path = MUD_DB if os.path.isabs(MUD_DB) else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), '..', MUD_DB
        )
        db = sqlite3.connect(db_path, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA foreign_keys=ON')
        _init_db(db)
        ctx.server.mud_db = db
    __package__[0]["callable"] = MUD


def __del__(ctx):
    global _ollama_client
    for task in list(_directors.values()):
        try:
            task.cancel()
        except Exception:
            pass
    _directors.clear()
    _worlds.clear()
    _ollama_client = None
    if hasattr(ctx.server, 'mud_ollama'):
        ctx.server.mud_ollama = None
    db = getattr(ctx.server, 'mud_db', None)
    if db is not None:
        try:
            db.commit()
            db.close()
        except Exception:
            pass
        ctx.server.mud_db = None
