function event = konaet_run_event(metadata, artifact, parent, salt)
%KONAET_RUN_EVENT Public, causal execution metadata; never pass private data.
required = {'artifactName','executionCommit','executionRepository','kind','runAttempt','runId','sourceCommit','sourceRepository'};
assert(isstruct(metadata) && isscalar(metadata) && isequal(sort(fieldnames(metadata)),required.'), ...
    'Konaet:Metadata','Unexpected metadata fields.');
names = fieldnames(metadata);
for i=1:numel(names)
    value=metadata.(names{i});
    assert(ischar(value) && isrow(value) && numel(value)<=160 && all(double(value)>=32 & double(value)<=126), ...
        'Konaet:Metadata','Metadata must be bounded ASCII strings.');
end
repos = {'7dsolv/RealidadeQuantica','7dsolv/konaet-bot','7dsol3/konaet-sovereign-spec'};
assert(ismember(metadata.sourceRepository,repos) && ismember(metadata.executionRepository,repos), ...
    'Konaet:Metadata','Repository not registered.');
for name={'sourceCommit','executionCommit'}
    assert(~isempty(regexp(metadata.(name{1}),'^[0-9a-f]{40}$','once')), 'Konaet:Metadata','Full Git SHA required.');
end
assert(ismember(metadata.kind,{'science','automation-validation','integration'}), 'Konaet:Metadata','Invalid kind.');
assert(~isempty(regexp(metadata.runId,'^[1-9][0-9]{0,19}$','once')) ...
    && ~isempty(regexp(metadata.runAttempt,'^[1-9][0-9]{0,3}$','once')), 'Konaet:Metadata','Exact decimal run identifiers required.');
assert(~isempty(regexp(metadata.artifactName,'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$','once')), ...
    'Konaet:Metadata','Artifact must have a simple name.');
assert(isa(artifact,'uint8') && isvector(artifact) && numel(artifact)<=16*1024*1024, 'Konaet:Metadata','Invalid artifact bytes.');
assert(ischar(parent) && ~isempty(regexp(parent,'^[0-9a-f]{64}$','once')), 'Konaet:Metadata','Parent event ID required.');
if nargin<4
    generator=java.security.SecureRandom(); raw=typecast(generator.generateSeed(32),'uint8');
    salt=lower(reshape(dec2hex(raw,2).',1,[]));
end
assert(ischar(salt) && ~isempty(regexp(salt,'^[0-9a-f]{64}$','once')), 'Konaet:Metadata','Invalid salt.');
document=metadata; document.schema='konaet.run-event.v1'; document.parentEventId=parent;
document.artifactSha256=sha(artifact); document=orderfields(document);
% All fields are ASCII strings. Sorted keys + compact JSON match the existing SDK.
canonical=uint8(jsonencode(document));
eventId=sha([uint8('KONAET/RUN-EVENT/v1') uint8(0) canonical]);
docHex=lower(reshape(dec2hex(canonical,2).',1,[]));
computed=konaet_receipt_frame(sprintf('%s\n%s\n-\n',salt,docHex));
frame=sprintf('%s\n%s\n%s\n',salt,docHex,computed.commitment);
event=struct('schema','konaet.public-run-receipt.v1','eventId',eventId, ...
    'document',document,'commitment',computed.commitment,'args',{computed.args},'frame',frame);
end

function value=sha(bytes)
md=java.security.MessageDigest.getInstance('SHA-256'); md.update(bytes);
value=lower(reshape(dec2hex(typecast(md.digest(),'uint8'),2).',1,[]));
end
