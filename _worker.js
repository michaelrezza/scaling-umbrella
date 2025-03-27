const includeOriginalConfigs = true;

const subLinks = [];
const cnfLinks = [
  "https://raw.githubusercontent.com/NiREvil/vless/main/sub/freedom",
  "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
  "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/EternityAir.txt"
];

const cleanIPLink = "https://raw.githubusercontent.com/coldwater-10/clash_rules/main/List%20of%20clean%20IPs.txt";
const operatorList = ["AST", "HWB", "IRC", "MBT", "MCI", "MKB", "PRS", "RTL", "SHT", "ZTL", "PIS", "DAT", "SAB", "ASR", "FAN", "ZTL", "SFR", "DID", "LAY", "MAH", "TAK", "PET", "AND", "RES", "AFR", "ARA", "SAM", "APT", "ALL", "PLUS", "TEST", "ENG", "FA", "IPV6", "IRCF", "ANTY"];

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const pathParts = url.pathname.replace(/^\/|\/$/g, "").split("/");
    const type = pathParts[0].toLowerCase();

    let cleanIPs = [];
    if (["sub", "clash"].includes(type)) {
      if (pathParts[1] !== undefined) {
        const operator = pathParts[1].toUpperCase();
        if (operatorList.includes(operator)) {
          cleanIPs = await fetch(cleanIPLink)
            .then(r => r.text())
            .then(t => t.split("\n").filter(line => line.includes(operator)).map(line => line.split(" ")[0].trim()));
        } else {
          cleanIPs = [operator.toLowerCase()];
        }
      }

      let configList = [];
      for (const subLink of subLinks) {
        try {
          configList = configList.concat(await fetch(subLink).then(r => r.text()).then(a => atob(a)).then(t => t.split("\n")));
        } catch { }
      }

      for (const cnfLink of cnfLinks) {
        try {
          configList = configList.concat(await fetch(cnfLink).then(r => r.text()).then(t => t.split("\n")));
        } catch { }
      }

      const vmessConfigs = configList.filter(c => c.startsWith("vmess://"));
      const trojanConfigs = configList.filter(c => c.startsWith("trojan://"));
      const ssConfigs = configList.filter(c => c.startsWith("ss://"));

      let mergedConfigList = [];

      if (type === "sub") {
        if (includeOriginalConfigs) mergedConfigList = mergedConfigList.concat(vmessConfigs);
        mergedConfigList = mergedConfigList.concat(
          vmessConfigs.map(decodeVmess).map(c => modifyConfig(c, url, cleanIPs)).map(encodeVmess)
        );
        if (includeOriginalConfigs) mergedConfigList = mergedConfigList.concat(trojanConfigs, ssConfigs);

        return new Response(btoa(mergedConfigList.join("\n")));
      } else { // clash
        if (includeOriginalConfigs) mergedConfigList = mergedConfigList.concat(vmessConfigs.map(decodeVmess).map(toClash));
        mergedConfigList = mergedConfigList.concat(
          vmessConfigs.map(decodeVmess).map(c => modifyConfig(c, url, cleanIPs)).map(toClash)
        );

        return new Response(toYaml(mergedConfigList));
      }
    }

    return fetch(new Request("https://" + url.pathname.replace(/^\/|\/$/g, ""), request));
  }
};

function encodeVmess(conf) {
  try { return "vmess://" + btoa(JSON.stringify(conf)); } catch { return null; }
}

function decodeVmess(conf) {
  try { return JSON.parse(atob(conf.substr(8))); } catch { return {}; }
}

function modifyConfig(conf, url, cleanIPs) {
  if (!conf || conf.tls !== "tls") return conf;
  
  conf.sni = url.hostname;
  conf.add = cleanIPs.length ? cleanIPs[Math.floor(Math.random() * cleanIPs.length)] : "cloudflare.com";
  conf.port = 443;
  conf.name = (conf.name || conf.ps) + "-Worker";
  return conf;
}

function toClash(conf) {
  if (!conf || !conf.id) return {};
  return {
    name: conf.name || conf.ps,
    type: "vmess",
    server: conf.add,
    port: conf.port,
    uuid: conf.id,
    alterId: 0,
    tls: true,
    cipher: "auto",
    servername: conf.sni,
    network: conf.net,
    "ws-opts": { path: conf.path, headers: { host: conf.host } }
  };
}

function toYaml(configList) {
  return `
proxies:
${configList.map(c => `  - ${JSON.stringify(c)}`).join("\n")}
`;
}
