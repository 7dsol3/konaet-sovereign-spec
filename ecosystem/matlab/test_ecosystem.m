function report = test_ecosystem(spec, lab, bot, output)
%TEST_ECOSYSTEM Known-answer interoperability, adversarial inputs, real sources.
addpath(fullfile(spec,'ecosystem','matlab'),fullfile(lab,'matlab'));
if ~isfolder(output), mkdir(output); end
vectors=jsondecode(fileread(fullfile(spec,'polyglot','vectors.json')));
checks=0;
for i=1:numel(vectors.cases)
    v=vectors.cases(i); frame=sprintf('%s\n%s\n%s\n',v.salt,v.documentHex,v.commitment);
    result=konaet_receipt_frame(frame);
    assert(result.matches && isequal(result.args,reshape(cellstr(string(v.args)),1,[]))); checks=checks+1;
    mismatch=frame; if mismatch(end-1)=='0', mismatch(end-1)='1'; else, mismatch(end-1)='0'; end
    compared=konaet_receipt_frame(mismatch); assert(~compared.matches); checks=checks+1;
    changed=frame; changed(end-1)='g'; rejects(@() konaet_receipt_frame(changed)); checks=checks+1;
end
first=vectors.cases(1); frame=sprintf('%s\n%s\n%s\n',first.salt,first.documentHex,first.commitment);
bad={'',frame(1:end-1),[frame char(10)],strrep(frame,char(10),sprintf('\r\n')), ...
    sprintf('%s\n0\n-\n',first.salt),sprintf('%s\n00\n-\n',first.salt), ...
    sprintf('%s\n%s\n-\n',first.salt,repmat('00',1,16385))};
for i=1:numel(bad), rejects(@() konaet_receipt_frame(bad{i})); checks=checks+1; end
maximum=konaet_receipt_frame(sprintf('%s\n%s\n-\n',first.salt,repmat('00',1,16384)));
assert(numel(maximum.commitment)==64); checks=checks+1;

specSha=revision(spec); labSha=revision(lab); botSha=revision(bot);
runId=getenv('GITHUB_RUN_ID'); if isempty(runId), runId='1'; end
attempt=getenv('GITHUB_RUN_ATTEMPT'); if isempty(attempt), attempt='1'; end
executionRepo=getenv('GITHUB_REPOSITORY'); if isempty(executionRepo), executionRepo='7dsol3/konaet-sovereign-spec'; end
if strcmp(executionRepo,'7dsolv/RealidadeQuantica'), executionSha=labSha; else, executionSha=specSha; end
metadata=struct('artifactName','wavepacket.csv','executionCommit',executionSha, ...
    'executionRepository',executionRepo,'kind','science','runAttempt',attempt,'runId',runId, ...
    'sourceCommit',labSha,'sourceRepository','7dsolv/RealidadeQuantica');
x=linspace(-40,40,1025); [~,p,width]=free_wavepacket(x,2,0.6,3);
assert(abs(trapz(x,p)-1)<1e-9 && abs(width-2*sqrt(1+(3/8)^2))<1e-12); checks=checks+1;
csv=sprintf('x,probability\n'); csv=[csv sprintf('%.17g,%.17g\n',[x;p])]; %#ok<AGROW>
write(fullfile(output,'wavepacket.csv'),uint8(csv));
science=konaet_run_event(metadata,uint8(csv),repmat('0',1,64));
reordered=konaet_run_event(orderfields(metadata,flipud(fieldnames(metadata))),uint8(csv),repmat('0',1,64),science.frame(1:64));
assert(strcmp(science.eventId,reordered.eventId) && strcmp(science.commitment,reordered.commitment)); checks=checks+1;
altered=konaet_run_event(metadata,uint8([csv '0']),repmat('0',1,64));
assert(~strcmp(science.eventId,altered.eventId)); checks=checks+1;
badMetadata=metadata; badMetadata.sourceRepository='foreign/repo'; rejects(@() konaet_run_event(badMetadata,uint8(csv),science.eventId)); checks=checks+1;
badMetadata=metadata; badMetadata.runId=9007199254740992; rejects(@() konaet_run_event(badMetadata,uint8(csv),science.eventId)); checks=checks+1;
badMetadata=metadata; badMetadata.sourceCommit='main'; rejects(@() konaet_run_event(badMetadata,uint8(csv),science.eventId)); checks=checks+1;
rejects(@() konaet_run_event(metadata,uint8(csv),'wrong-parent')); checks=checks+1;

addpath(fullfile(bot,'tests'),bot,fullfile(bot,'activation'));
botReport=run_konaet_tests(bot,fullfile(output,'bot'));
activation=run_activation_tests(bot,fullfile(output,'bot'));
assert(botReport.failed==0 && activation.passed==activation.total);
metadata.kind='automation-validation'; metadata.sourceRepository='7dsolv/konaet-bot'; metadata.sourceCommit=botSha;
metadata.artifactName='bot-validation.json'; validationBytes=uint8(jsonencode(struct('contracts',botReport,'activation',activation)));
write(fullfile(output,metadata.artifactName),validationBytes);
automation=konaet_run_event(metadata,validationBytes,science.eventId);
metadata.kind='integration'; metadata.sourceRepository='7dsol3/konaet-sovereign-spec'; metadata.sourceCommit=specSha;
metadata.artifactName='causal-inputs.txt'; joined=uint8(sprintf('%s\n%s\n',science.eventId,automation.eventId));
write(fullfile(output,metadata.artifactName),joined);
integration=konaet_run_event(metadata,joined,automation.eventId);
events={science,automation,integration};
report=struct('schema','konaet.ecosystem-validation.v1','checksPassed',checks, ...
    'knownAnswerVectors',numel(vectors.cases),'botContracts',botReport.passed,'botActivation',activation.passed, ...
    'sources',struct('sovereign',specSha,'laboratory',labSha,'bot',botSha), ...
    'events',{events},'appAuthenticationTested',false,'physicalHardwareTested',false, ...
    'postQuantumFinalityTested',false);
write(fullfile(output,'ecosystem-report.json'),uint8(jsonencode(report,PrettyPrint=true)));
write(fullfile(output,'frame.txt'),uint8(integration.frame));
v=struct('name','real-three-repository-event','salt',integration.frame(1:64), ...
    'documentHex',lower(reshape(dec2hex(uint8(jsonencode(integration.document)),2).',1,[])), ...
    'commitment',integration.commitment,'args',{integration.args});
write(fullfile(output,'receipt-vector.json'),uint8(jsonencode(struct('schema','konaet.polyglot-vectors.v1','cases',{{v}}))));
konaet_ecosystem_visual(output,x,p,report);
fprintf('Ecosystem: %d checks + %d bot contracts + %d activation checks.\n',checks,botReport.passed,activation.passed);
end

function value=revision(root)
previous=pwd; guard=onCleanup(@() cd(previous)); cd(root); %#ok<NASGU>
[code,text]=system('git rev-parse HEAD'); value=strtrim(text);
assert(code==0 && ~isempty(regexp(value,'^[0-9a-f]{40}$','once')),'Full source revision required.');
[code,status]=system('git status --porcelain --untracked-files=normal');
assert(code==0 && isempty(strtrim(status)),'Konaet:DirtySource','Commit sources before generating execution evidence.');
end
function rejects(operation)
denied=false; try, operation(); catch exception, denied=startsWith(exception.identifier,'Konaet:'); end
assert(denied,'Expected explicit input rejection.');
end
function write(path,bytes)
fid=fopen(path,'wb'); assert(fid>=0); guard=onCleanup(@() fclose(fid)); %#ok<NASGU>
assert(fwrite(fid,bytes,'uint8')==numel(bytes));
end
