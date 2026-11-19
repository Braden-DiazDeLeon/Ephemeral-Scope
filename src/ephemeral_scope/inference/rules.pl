%% Risk inference rules for Ephemeral Scope.
%%
%% Two separate questions are asked of the same evidence:
%%
%%   migration_risk/2    How likely is this upgrade to break the project?
%%   upgrade_urgency/2   How badly does the project need to upgrade anyway?
%%
%% They are kept apart on purpose. A vulnerability fixed by the target
%% version is a reason to upgrade, not a hazard of upgrading; folding it
%% into one score would make a security fix look like an incompatibility
%% and could talk a user out of the very upgrade that protects them.
%%
%% Load together with a generated fact file:
%%   swipl -g "consult('rules.pl'), consult('facts.pl')" -t halt

:- discontiguous migration_risk_evidence/3.
:- discontiguous urgency_evidence/3.

%% Predicates supplied by fact_builder. Declared so rules referring to a
%% category absent from a given analysis fail quietly instead of raising.
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

%% Severity ordering

severity_rank(low, 1).
severity_rank(medium, 2).
severity_rank(high, 3).

stronger(A, B) :-
    severity_rank(A, RankA),
    severity_rank(B, RankB),
    RankA >= RankB.

%% Relevance

%% Mirrors RELEVANCE_THRESHOLD in ml.relevance_matcher.
relevance_threshold(0.5).

relevant_change(Change) :-
    release_relevance(Change, Score),
    relevance_threshold(Threshold),
    Score >= Threshold.

%% A statement supported only by the TF-IDF model is a suggestion. It may
%% appear in the report but must not on its own raise a high finding.
corroborated(Change) :-
    \+ model_only(Change).

%% Migration risk: will this upgrade break the project?

%% A symbol the project actually calls has been removed.
migration_risk_evidence(high, removed_symbol_in_use, Symbol) :-
    affected_usage(_, _, Symbol, removed).

migration_risk_evidence(high, incompatible_signature_in_use, Symbol) :-
    affected_usage(_, _, Symbol, ChangeType),
    member(ChangeType, [parameter_added_required, parameter_removed,
                        parameter_renamed]).

%% A breaking change the project looks exposed to, but which we could not
%% tie to a specific call site.
migration_risk_evidence(medium, breaking_change_reported, Change) :-
    release_change(Change, breaking_change),
    relevant_change(Change),
    corroborated(Change).

migration_risk_evidence(medium, behavioral_change_relevant, Change) :-
    release_change(Change, behavioral_change),
    relevant_change(Change),
    corroborated(Change).

migration_risk_evidence(medium, signature_changed_in_use, Symbol) :-
    affected_usage(_, _, Symbol, signature_changed).

migration_risk_evidence(medium, moved_symbol_in_use, Symbol) :-
    affected_usage(_, _, Symbol, moved).

migration_risk_evidence(low, default_changed_in_use, Symbol) :-
    affected_usage(_, _, Symbol, default_changed).

migration_risk_evidence(low, deprecation_relevant, Change) :-
    release_change(Change, deprecation),
    relevant_change(Change).

%% Bug fixes alone are the quiet case: something changed, nothing we can
%% see breaks.
migration_risk_evidence(low, bug_fixes_only, Change) :-
    release_change(Change, bug_fix).

migration_risk(Level, Reasons) :-
    findall(L-R-S, migration_risk_evidence(L, R, S), Evidence),
    (   Evidence == []
    ->  Level = low, Reasons = []
    ;   findall(L, member(L-_-_, Evidence), Levels),
        highest(Levels, Level),
        findall(R-S, member(Level-R-S, Evidence), Reasons)
    ).

%% Upgrade urgency: how badly is the upgrade needed?

%% Still exposed after upgrading. The upgrade does not resolve this, so it
%% is urgent but also not a reason to avoid the upgrade.
urgency_evidence(high, target_still_vulnerable, Advisory) :-
    upgrade(Package, _, Target),
    vulnerable_version(Package, Target, Advisory).

%% The upgrade closes a known hole. The single most important case to keep
%% out of migration_risk.
urgency_evidence(high, fixes_known_vulnerability, Advisory) :-
    upgrade(Package, _, Target),
    fixed_version(Package, Target, Advisory).

urgency_evidence(medium, security_fix_reported, Change) :-
    release_change(Change, security_fix),
    corroborated(Change).

urgency_evidence(low, bug_fixes_available, Change) :-
    release_change(Change, bug_fix).

upgrade_urgency(Level, Reasons) :-
    findall(L-R-A, urgency_evidence(L, R, A), Evidence),
    (   Evidence == []
    ->  Level = low, Reasons = []
    ;   findall(L, member(L-_-_, Evidence), Levels),
        highest(Levels, Level),
        findall(R-A, member(Level-R-A, Evidence), Reasons)
    ).

%% Shared helpers

highest(Levels, Highest) :-
    findall(Rank-Level, (member(Level, Levels), severity_rank(Level, Rank)),
            Ranked),
    sort(0, @>=, Ranked, [_-Highest|_]).

%% Retained for the existing report field. Deliberately only the migration
%% dimension: overall_risk answers "is this upgrade dangerous", and a
%% security fix does not make an upgrade dangerous.
overall_risk(Level) :-
    migration_risk(Level, _).

%% Test recommendations

recommended_test(TestFile) :-
    affected_usage(SourceFile, _, _, _),
    test_covers(TestFile, SourceFile).
