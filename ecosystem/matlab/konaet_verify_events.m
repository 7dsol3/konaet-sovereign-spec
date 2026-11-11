function verified=konaet_verify_events(events,directory,trust)
%KONAET_VERIFY_EVENTS Recompute artifact hashes, causal links and commitments.
% Trust must come from the expected source revisions and execution context,
% independently of the event document being verified.
if iscell(events), events=[events{:}]; end
assert(isstruct(events) && numel(events)==3,'Konaet:Evidence','Three events required.');
repositories={'7dsolv/RealidadeQuantica','7dsolv/konaet-bot','7dsol3/konaet-sovereign-spec'};
revisions={trust.sources.laboratory,trust.sources.bot,trust.sources.sovereign};
kinds={'science','automation-validation','integration'};
files={'wavepacket.csv','bot-validation.json','causal-inputs.txt'};
metadataNames={'artifactName','executionCommit','executionRepository','kind','runAttempt','runId','sourceCommit','sourceRepository'};
parent=repmat('0',1,64); ids=cell(1,3);
for i=1:3
    e=events(i); d=e.document;
    assert(strcmp(e.schema,'konaet.public-run-receipt.v1') && strcmp(d.schema,'konaet.run-event.v1') ...
        && strcmp(d.sourceRepository,repositories{i}) && strcmp(d.sourceCommit,revisions{i}) ...
        && strcmp(d.kind,kinds{i}) && strcmp(d.artifactName,files{i}) ...
        && strcmp(d.executionRepository,trust.executionRepository) ...
        && strcmp(d.executionCommit,trust.executionCommit) ...
        && strcmp(d.runId,trust.runId) && strcmp(d.runAttempt,trust.runAttempt), ...
        'Konaet:Evidence','Event identity differs from trusted context.');
    assert(strcmp(d.parentEventId,parent) && ischar(e.frame) && numel(e.frame)>=64, ...
        'Konaet:Evidence','Broken causal link or invalid frame.');
    filename=fullfile(directory,files{i}); info=dir(filename);
    assert(numel(info)==1 && ~info.isdir && info.bytes<=16*1024*1024,'Konaet:Evidence','Invalid artifact file.');
    fid=fopen(filename,'rb'); assert(fid>=0,'Konaet:Evidence','Cannot read artifact.');
    cleanup=onCleanup(@() fclose(fid)); bytes=fread(fid,inf,'*uint8').'; clear cleanup;
    if i==3
        expected=uint8(sprintf('%s\n%s\n',ids{1},ids{2}));
        assert(isequal(bytes,expected),'Konaet:Evidence','Integration inputs differ from predecessor IDs.');
    end
    metadata=struct();
    for j=1:numel(metadataNames), metadata.(metadataNames{j})=d.(metadataNames{j}); end
    actual=konaet_run_event(metadata,bytes,parent,e.frame(1:64));
    assert(iscell(e.args) && numel(e.args)==2 && all(cellfun(@ischar,e.args)), ...
        'Konaet:Evidence','Exact decimal string arguments required.');
    assert(strcmp(actual.eventId,e.eventId) && strcmp(actual.commitment,e.commitment) ...
        && strcmp(actual.frame,e.frame) && isequal(actual.args,reshape(e.args,1,[])) ...
        && isequal(actual.document,orderfields(d)), 'Konaet:Evidence','Artifact, event or commitment was altered.');
    ids{i}=actual.eventId; parent=actual.eventId;
end
verified=struct('verified',true,'artifactFilesVerified',3,'eventIds',{ids}, ...
    'finalCommitment',events(3).commitment,'scope','artifact-hashes-causal-links-and-trusted-source-context');
end
