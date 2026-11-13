var http = require('http');
var fs = require('fs');
var path = require('path');

var configPath = path.join(__dirname, 'config.json');
if (!fs.existsSync(configPath)) {
  console.error('Khong tim thay file cau hinh:', configPath);
  process.exit(1);
}
var appCfg = JSON.parse(fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, ''));
var gCfg = appCfg.grafanaSync || {};
var gHost = gCfg.host || '127.0.0.1';
var gPort = Number(gCfg.port) || 3000;
var gDashUid = gCfg.dashboardUid || 'totolink-network-ap-v1';
var gUser = gCfg.username || 'admin';
var gPass = gCfg.password || '';

if (!gPass) {
  console.error('Vui long cau hinh grafanaSync.password trong config.json');
  process.exit(1);
}

var auth = (Buffer.from ? Buffer.from(gUser + ':' + gPass) : new Buffer(gUser + ':' + gPass)).toString('base64');

http.get({
  hostname: gHost,
  port: gPort,
  path: '/api/dashboards/uid/' + gDashUid,
  headers: { 'Authorization': 'Basic ' + auth }
}, function(res) {
  var raw = '';
  res.on('data', function(c) { raw += c; });
  res.on('end', function() {
    var d = JSON.parse(raw);
    var dash = d.dashboard;

    dash.refresh = '5s'; // Auto refresh every 5s for snappy real-time responsiveness

    dash.panels.forEach(function(p) {
      // Panel 6: Stat panel
      if (p.id === 6) {
        p.title = 'Tổng Băng Thông Mạng';
        p.fieldConfig = p.fieldConfig || {};
        p.fieldConfig.defaults = p.fieldConfig.defaults || {};
        p.fieldConfig.defaults.unit = 'bps';
        p.fieldConfig.defaults.thresholds = {
          mode: 'absolute',
          steps: [
            { color: 'blue', value: 0 },
            { color: 'green', value: 15000000 },
            { color: 'orange', value: 35000000 }
          ]
        };
        p.targets = [
          {
            datasource: { type: 'prometheus', uid: '${DS_PROMETHEUS}' },
            editorMode: 'code',
            expr: 'sum(rate(ap_network_receive_bytes_total{model=~"$model", ap_name=~"$ap"}[2m]) + rate(ap_network_transmit_bytes_total{model=~"$model", ap_name=~"$ap"}[2m])) * 8 or vector(0)',
            instant: true,
            range: false,
            refId: 'A'
          }
        ];
      }

      // Row 16
      else if (p.id === 16) {
        p.title = '📶 LƯU LƯỢNG MẠNG & BĂNG THÔNG TRUYỀN TẢI (TRAFFIC ANALYSIS)';
      }

      // Panel 9: Total Traffic Timeseries (Download / Upload)
      else if (p.id === 9) {
        p.title = 'Tổng Lưu Lượng Băng Thông Hệ Thống (Download / Upload)';
        p.fieldConfig = p.fieldConfig || {};
        p.fieldConfig.defaults = p.fieldConfig.defaults || {};
        p.fieldConfig.defaults.unit = 'bps';
        p.fieldConfig.defaults.custom = p.fieldConfig.defaults.custom || {};
        p.fieldConfig.defaults.custom.axisLabel = 'Băng Thông';
        p.fieldConfig.defaults.custom.lineInterpolation = 'smooth';
        p.fieldConfig.defaults.custom.fillOpacity = 15;

        p.options = p.options || {};
        p.options.legend = {
          calcs: ['lastNotNull', 'max', 'mean'],
          displayMode: 'table',
          placement: 'bottom',
          showLegend: true
        };

        p.targets = [
          {
            datasource: { type: 'prometheus', uid: '${DS_PROMETHEUS}' },
            editorMode: 'code',
            expr: 'sum(rate(ap_network_receive_bytes_total{model=~"$model", ap_name=~"$ap"}[2m])) * 8',
            legendFormat: 'Tải về (Download)',
            range: true,
            refId: 'A'
          },
          {
            datasource: { type: 'prometheus', uid: '${DS_PROMETHEUS}' },
            editorMode: 'code',
            expr: 'sum(rate(ap_network_transmit_bytes_total{model=~"$model", ap_name=~"$ap"}[2m])) * 8',
            legendFormat: 'Tải lên (Upload)',
            range: true,
            refId: 'B'
          }
        ];
      }

      // Panel 10: Top 5 APs Traffic
      else if (p.id === 10) {
        p.title = 'Top 5 AP Tiêu Thụ Băng Thông Cao Nhất';
        p.fieldConfig = p.fieldConfig || {};
        p.fieldConfig.defaults = p.fieldConfig.defaults || {};
        p.fieldConfig.defaults.unit = 'bps';
        p.fieldConfig.defaults.custom = p.fieldConfig.defaults.custom || {};
        p.fieldConfig.defaults.custom.axisLabel = 'Băng Thông';
        p.fieldConfig.defaults.custom.lineInterpolation = 'smooth';
        p.fieldConfig.defaults.custom.fillOpacity = 10;

        p.options = p.options || {};
        p.options.legend = {
          calcs: ['lastNotNull', 'max'],
          displayMode: 'table',
          placement: 'bottom',
          showLegend: true
        };

        p.targets = [
          {
            datasource: { type: 'prometheus', uid: '${DS_PROMETHEUS}' },
            editorMode: 'code',
            expr: 'topk(5, (rate(ap_network_receive_bytes_total{model=~"$model", ap_name=~"$ap"}[2m]) + rate(ap_network_transmit_bytes_total{model=~"$model", ap_name=~"$ap"}[2m])) * 8)',
            legendFormat: '{{ap_name}} ({{ap_ip}})',
            range: true,
            refId: 'A'
          }
        ];
      }
    });

    var payload = JSON.stringify({
      dashboard: dash,
      overwrite: true,
      message: 'Restore dynamic real-time bandwidth metrics with 5s refresh and smooth curves'
    });

    var saveReq = http.request({
      hostname: gHost,
      port: gPort,
      path: '/api/dashboards/db',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Authorization': 'Basic ' + auth
      }
    }, function(saveRes) {
      var resBody = '';
      saveRes.on('data', function(c) { resBody += c; });
      saveRes.on('end', function() {
        console.log('Grafana Save Status Code:', saveRes.statusCode);
        console.log('Grafana Save Response:', resBody);
      });
    });

    saveReq.on('error', function(err) {
      console.error('Save failed:', err.message);
    });

    saveReq.write(payload);
    saveReq.end();
  });
}).on('error', function(err) {
  console.error('Fetch failed:', err.message);
});
