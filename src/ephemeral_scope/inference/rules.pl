%% Risk inference rules for Ephemeral Scope.
%%
%% Two separate questions are asked of the same facts:
%%
%%   migration_risk(Level, Rule, Subject)     will this upgrade break me?
%%   upgrade_urgency(Level, Rule, Subject)    do I need it regardless?
%%
%% They are kept apart on purpose. A vulnerability fixed by the target
%% version is a reason to upgrade, not a hazard of upgrading; folding it
%% into one score would report a security fix as an incompatibility and
%% could talk a user out of the very upgrade that protects them.
%%

%%
%% Only high- and medium-risk rules are implemented so far. Low-risk rules
%% (deprecations, default changes, bug-fix-only releases) are deliberately
%% absent until these are proven; their absence is harmless because an
%% analysis with no firing rule already reports `low`.
%%
%% Manual use from a terminal:
%%
%%   swipl -q -g "consult('rules.pl'), consult('facts.pl'), report" -t halt
%%
%% or interactively:
%%
%%   swipl rules.pl
%%   ?- consult('facts.pl').
%%   ?- migration_risk(Level, Rule, Subject).
%%   ?- upgrade_urgency(Level, Rule, Advisory).
%%   ?- report.

:- discontiguous migration_risk/3.
:- discontiguous upgrade_urgency/3.

%% Predicates supplied by fact_builder. Declared dynamic so a rule naming a
%% predicate absent from this particular analysis fails quietly instead of
%% raising an existence error.
:- dynamic package/1.
:- dynamic upgrade/3.
:- dynamic uses_symbol/2.
:- dynamic usage_site/4.
:- dynamic api_change/2.
:- dynamic affected_usage/4.
:- dynamic release_change/2.
:- dynamic release_unclassified/1.
:- dynamic release_relevance/2.
:- dynamic release_mentions/2.
:- dynamic classification_source/2.
:- dynamic classifier_agreement/1.
:- dynamic model_only/1.
:- dynamic vulnerable_version/3.
:- dynamic fixed_version/3.
:- dynamic test_covers/2.

%% Thresholds

%% A breaking note needs only a plausible connection to the project; a
%% behavioural note needs a strong one, because behavioural notes are far
%% more numerous and a weak match produces noise. 0.5 is a parameter-name
%% match, 0.7 a symbol-name match. See ml.relevance_matcher.
breaking_note_threshold(0.5).
behavior_note_threshold(0.7).

%% Vulnerability helpers

vulnerable_current_version(Advisory) :-
    upgrade(Package, Current, _),
    vulnerable_version(Package, Current, Advisory).

%% The target is safe from an advisory when no fact says otherwise.
%%
%% Advisory is bound from the current version first. Calling \+ with an
%% unbound Advisory would ask "is there no advisory affecting the target at
%% all", which is a different and much weaker claim -- the classic
%% floundering-negation bug.
safe_target_version(Advisory) :-
    vulnerable_current_version(Advisory),
    upgrade(Package, _, Target),
    \+ vulnerable_version(Package, Target, Advisory).

%% Migration risk: will this upgrade break the project?

%% An API the project calls is gone.
migration_risk(high, removed_used_api, Symbol) :-
    affected_usage(_, _, Symbol, removed).

%% An API the project calls still exists but is no longer call-compatible.
%% The parameter change types are grouped under this one name rather than
%% given three more: from a caller's point of view they are the same
%% failure, and the report reads better for it.
migration_risk(high, changed_used_signature, Symbol) :-
    affected_usage(_, _, Symbol, ChangeType),
    member(ChangeType, [signature_changed, parameter_added_required,
                        parameter_removed, parameter_renamed]).

%% A breaking change announced in the release notes that looks connected to
%% this project, where no specific call site could be identified.
migration_risk(medium, relevant_breaking_note, Change) :-
    release_change(Change, breaking_change),
    release_relevance(Change, Score),
    breaking_note_threshold(Threshold),
    Score >= Threshold,
    corroborated(Change).

migration_risk(medium, relevant_behavior_change, Change) :-
    release_change(Change, behavioral_change),
    release_relevance(Change, Score),
    behavior_note_threshold(Threshold),
    Score >= Threshold,
    corroborated(Change).

%% ---------------------------------------------------------------------
%% Upgrade urgency: how badly is the upgrade needed?
%% ---------------------------------------------------------------------

%% The upgrade closes a known hole. The single most important case to keep
%% out of migration_risk.
upgrade_urgency(high, fixes_known_vulnerability, Advisory) :-
    vulnerable_current_version(Advisory),
    safe_target_version(Advisory).

%% Still exposed after upgrading: urgent, but not an argument against the
%% upgrade either.
upgrade_urgency(high, target_remains_vulnerable, Advisory) :-
    upgrade(Package, _, Target),
    vulnerable_version(Package, Target, Advisory).

upgrade_urgency(medium, reported_security_fix, Change) :-
    release_change(Change, security_fix),
    corroborated(Change).

%% Confidence

confidence_support(Change, classifier_agreement) :-
    classifier_agreement(Change).

confidence_support(Change, matched_project_symbol) :-
    release_mentions(Change, _).

%% A statement supported only by the TF-IDF model is a suggestion. It may
%% appear in the report but must not on its own raise a finding.
corroborated(Change) :-
    \+ model_only(Change).

%% Aggregation

severity_rank(low, 1).
severity_rank(medium, 2).
severity_rank(high, 3).

highest([], low).
highest(Levels, Highest) :-
    Levels \== [],
    findall(Rank-Level,
            (member(Level, Levels), severity_rank(Level, Rank)),
            Ranked),
    sort(0, @>=, Ranked, [_-Highest|_]).

migration_risk_level(Level) :-
    findall(L, migration_risk(L, _, _), Levels),
    highest(Levels, Level).

upgrade_urgency_level(Level) :-
    findall(L, upgrade_urgency(L, _, _), Levels),
    highest(Levels, Level).

%% Retained for the existing report field. Deliberately the migration
%% dimension alone: overall_risk answers "is this upgrade dangerous", and a
%% security fix does not make an upgrade dangerous.
overall_risk(Level) :-
    migration_risk_level(Level).

%% Test recommendations

recommended_test(TestFile) :-
    affected_usage(SourceFile, _, _, _),
    test_covers(TestFile, SourceFile).

%% Terminal reporting

%% Deduplicated: a symbol used at several call sites would otherwise be
%% reported once per site.
findings(Dimension, Sorted) :-
    (   Dimension == migration
    ->  findall(L-R-S, migration_risk(L, R, S), Raw)
    ;   findall(L-R-S, upgrade_urgency(L, R, S), Raw)
    ),
    sort(Raw, Sorted).

report :-
    migration_risk_level(MigrationLevel),
    upgrade_urgency_level(UrgencyLevel),
    format("migration risk:  ~w~n", [MigrationLevel]),
    findings(migration, MigrationFindings),
    forall(member(L-R-S, MigrationFindings),
           format("  [~w] ~w: ~w~n", [L, R, S])),
    format("upgrade urgency: ~w~n", [UrgencyLevel]),
    findings(urgency, UrgencyFindings),
    forall(member(L-R-A, UrgencyFindings),
           format("  [~w] ~w: ~w~n", [L, R, A])),
    forall(recommended_test(T), format("recommended test: ~w~n", [T])).
