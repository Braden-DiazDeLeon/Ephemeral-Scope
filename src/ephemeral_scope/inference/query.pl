%% Machine-readable interface to rules.pl.
%%
%% rules.pl is the statement of policy and is meant to be read by a human
%% and queried. This file is the interface Python drives: it answers
%% the same questions but emits JSON on standard output, so the boundary
%% between the two languages is one well-defined document rather than a
%% screen-scrape of format/2 output.
%%
%% Subjects are symbols, file paths and
%% advisory ids; any of them may contain spaces, quotes or Unicode, so a
%% delimiter-based text format would be ambiguous exactly where it hurts.
%%
%% Used by inference.prolog_risk_engine:
%%
%%   swipl -q -g "consult('query.pl'), consult('facts.pl'), emit_findings" -t halt

:- ensure_loaded(rules).

:- use_module(library(http/json)).

%% Both dimensions, tagged, so one query returns everything.
finding(migration, Level, Rule, Subject) :-
    migration_risk(Level, Rule, Subject).
finding(urgency, Level, Rule, Subject) :-
    upgrade_urgency(Level, Rule, Subject).

%% The call sites behind a finding whose subject is a symbol. Empty for
%% findings about release notes or advisories, which have no location.
finding_sites(Subject, Sites) :-
    findall(_{file: File, line: Line, change: Change},
            affected_usage(File, Line, Subject, Change),
            Raw),
    sort(Raw, Sites).

finding_support(Subject, Kinds) :-
    findall(Kind, confidence_support(Subject, Kind), Raw),
    sort(Raw, Kinds).

finding_dict(Dict) :-
    finding(Dimension, Level, Rule, Subject),
    finding_sites(Subject, Sites),
    finding_support(Subject, Support),
    Dict = _{dimension: Dimension, level: Level, rule: Rule,
             subject: Subject, sites: Sites, support: Support}.

%% sort/2 removes duplicates: one symbol used at several call sites would
%% otherwise yield the same finding once per site. The sites travel inside
%% the finding instead.
inference_dict(Dict) :-
    findall(Finding, finding_dict(Finding), RawFindings),
    sort(RawFindings, Findings),
    migration_risk_level(Migration),
    upgrade_urgency_level(Urgency),
    findall(Test, recommended_test(Test), RawTests),
    sort(RawTests, Tests),
    Dict = _{migration_risk: Migration,
             upgrade_urgency: Urgency,
             findings: Findings,
             recommended_tests: Tests}.

emit_findings :-
    inference_dict(Dict),
    json_write_dict(current_output, Dict),
    nl.
