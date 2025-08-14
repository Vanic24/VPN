const axios = require('axios');
const { Base64 } = require('js-base64');
const yaml = require('js-yaml');
const fs = require('fs');

(async () => {
  const SUB_URL = process.env.SUB_URL;
  if (!SUB_URL) { console.error("Missing SUB_URL secret"); process.exit(1); }

  function parseVmess(link) {
    try {
      const json = JSON.parse(Base64.decode(link.slice(8)));
      const net = (json.net || 'tcp').toLowerCase();
      const p = {
        name: json.ps || 'vmess',
        type: 'vmess',
        server: json.add,
        port: Number(json.port),
        uuid: json.id,
        alterId: Number(json.aid || 0),
        cipher: 'auto',
        tls: (json.tls || '').toLowerCase() === 'tls',
        network: net
      };
      if (json.sni) p.servername = json.sni;
      if (net === 'ws') p['ws-opts'] = { path: json.path || '', headers: { Host: json.host || '' } };
      if (net === 'grpc') p['grpc-opts'] = { 'grpc-service-name': json.path || '' };
      return p;
    } catch {
      return null;
    }
  }

  console.log('📥 Fetching subscription...');
  const res = await axios.get(SUB_URL, { responseType: 'text' });
  let decoded;
  try { decoded = Base64.decode(res.data.trim()); } 
  catch { decoded = Buffer.from(res.data.trim(), 'base64').toString('utf8'); }

  let lines = decoded.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  // Remove first two nodes
  lines = lines.slice(2);

  const proxies = lines.map(line => {
    if (line.startsWith('vmess://')) return parseVmess(line);
    return null;
  }).filter(Boolean);

  console.log(`🔹 Total proxies parsed: ${proxies.length}`);

  const clashConfig = {
    proxies: proxies,
    'proxy-groups': [
      { name: 'Auto', type: 'url-test', proxies: proxies.map(p=>p.name), url: 'http://www.gstatic.com/generate_204', interval: 300 }
    ],
    rules: ['MATCH,Auto']
  };

  const yamlData = yaml.dump(clashConfig, { noRefs: true, lineWidth: 120 });
  fs.writeFileSync('9PB', yamlData, 'utf8');
  console.log('✅ YAML written to ./9PB');
})();
