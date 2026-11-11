function result = konaet_receipt_frame(frame)
%KONAET_RECEIPT_FRAME KRP-0001: exact bytes, SHA-256 and two decimal u128s.
% No JSON normalization occurs here. Input is the existing three-line frame.
assert(ischar(frame) && isrow(frame) && numel(frame) <= 32900, 'Konaet:Frame', 'Invalid frame.');
assert(all(double(frame) < 128) && ~any(frame == char(13)), 'Konaet:Frame', 'ASCII/LF required.');
lines = strsplit(frame, char(10), 'CollapseDelimiters', false);
assert(numel(lines) == 4 && isempty(lines{4}), 'Konaet:Frame', 'Exactly three LF-terminated lines required.');
salt = lines{1}; doc = lines{2}; expected = lines{3};
assert(~isempty(regexp(salt, '^[0-9a-f]{64}$', 'once')), 'Konaet:Frame', 'Invalid salt.');
assert(numel(doc) >= 4 && numel(doc) <= 32768 && mod(numel(doc),2) == 0 ...
    && ~isempty(regexp(doc, '^[0-9a-f]+$', 'once')), 'Konaet:Frame', 'Invalid document bytes.');
assert(strcmp(expected,'-') || ~isempty(regexp(expected,'^[0-9a-f]{64}$','once')), ...
    'Konaet:Frame', 'Invalid expected commitment.');
bytes = [uint8('KONAET/SOCIAL-RECEIPT/v1') uint8(0) unhex(salt) unhex(doc)];
md = java.security.MessageDigest.getInstance('SHA-256'); md.update(bytes);
commitment = lower(reshape(dec2hex(typecast(md.digest(),'uint8'),2).',1,[]));
result = struct('commitment',commitment, 'args',{{decimal(commitment(1:32)), decimal(commitment(33:64))}}, 'matches',[]);
if ~strcmp(expected,'-'), result.matches = strcmp(expected,commitment); end
end

function bytes = unhex(text)
bytes = uint8(sscanf(text,'%2x').');
end

function text = decimal(hex)
% Decimal digit arithmetic avoids any floating-point conversion of a u128.
digits = 0;
for ch = hex
    carry = find('0123456789abcdef' == ch,1)-1;
    for j = 1:numel(digits)
        value = 16*digits(j)+carry; digits(j) = mod(value,10); carry = floor(value/10);
    end
    while carry > 0, digits(end+1) = mod(carry,10); carry = floor(carry/10); end %#ok<AGROW>
end
text = char(fliplr(digits)+'0');
end
