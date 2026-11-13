var http = require('http');

http.get('http://localhost:9100/metrics', function(res) {
  var data = '';
  res.on('data', function(c) { data += c; });
  res.on('end', function() {
    var lines = data.split('\n');
    var apMap = {};
    var totalRx = 0;
    var totalTx = 0;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.indexOf('#') === 0) continue;

      if (line.indexOf('ap_network_receive_bytes_total{') === 0) {
        var parts = line.split(' ');
        var val = parseFloat(parts[parts.length - 1]);
        if (!isNaN(val)) totalRx += val;

        var macMatch = line.match(/ap_mac="([^"]+)"/);
        var nameMatch = line.match(/ap_name="([^"]+)"/);
        if (macMatch && nameMatch) {
          var mac = macMatch[1];
          if (!apMap[mac]) apMap[mac] = { mac: mac, name: nameMatch[1], rx: 0, tx: 0 };
          apMap[mac].rx = val;
        }
      } else if (line.indexOf('ap_network_transmit_bytes_total{') === 0) {
        var parts2 = line.split(' ');
        var val2 = parseFloat(parts2[parts2.length - 1]);
        if (!isNaN(val2)) totalTx += val2;

        var macMatch2 = line.match(/ap_mac="([^"]+)"/);
        var nameMatch2 = line.match(/ap_name="([^"]+)"/);
        if (macMatch2 && nameMatch2) {
          var mac2 = macMatch2[1];
          if (!apMap[mac2]) apMap[mac2] = { mac: mac2, name: nameMatch2[1], rx: 0, tx: 0 };
          apMap[mac2].tx = val2;
        }
      }
    }

    var list = Object.keys(apMap).map(function(k) { return apMap[k]; });
    list.sort(function(a, b) { return (b.rx + b.tx) - (a.rx + a.tx); });

    console.log('================================================================');
    console.log('📊 KẾT QUẢ TỔNG HỢP LƯU LƯỢNG TỪ HTTP://LOCALHOST:9100/METRICS');
    console.log('================================================================');
    console.log('Tổng số AP được ghi nhận: ' + list.length + ' AP');
    console.log('');
    console.log('1. TỔNG DUNG LƯỢNG DOWNLOAD (ap_network_receive_bytes_total):');
    console.log('   - Bytes:  ' + totalRx.toLocaleString() + ' Bytes');
    console.log('   - KB:     ' + (totalRx / 1024).toFixed(2) + ' KB');
    console.log('   - MB:     ' + (totalRx / (1024 * 1024)).toFixed(2) + ' MB');
    console.log('   - GB:     ' + (totalRx / (1024 * 1024 * 1024)).toFixed(3) + ' GB');
    console.log('');
    console.log('2. TỔNG DUNG LƯỢNG UPLOAD (ap_network_transmit_bytes_total):');
    console.log('   - Bytes:  ' + totalTx.toLocaleString() + ' Bytes');
    console.log('   - KB:     ' + (totalTx / 1024).toFixed(2) + ' KB');
    console.log('   - MB:     ' + (totalTx / (1024 * 1024)).toFixed(2) + ' MB');
    console.log('   - GB:     ' + (totalTx / (1024 * 1024 * 1024)).toFixed(3) + ' GB');
    console.log('');
    console.log('3. TỔNG LƯU LƯỢNG TOÀN HỆ THỐNG (Download + Upload):');
    var totalAll = totalRx + totalTx;
    console.log('   - Bytes:  ' + totalAll.toLocaleString() + ' Bytes');
    console.log('   - MB:     ' + (totalAll / (1024 * 1024)).toFixed(2) + ' MB');
    console.log('   - GB:     ' + (totalAll / (1024 * 1024 * 1024)).toFixed(3) + ' GB');
    console.log('================================================================');
    console.log('');
    console.log('TOP 10 ACCESS POINT TIÊU THỤ NHIỀU DUNG LƯỢNG NHẤT:');
    list.slice(0, 10).forEach(function(ap, idx) {
      var apTotal = ap.rx + ap.tx;
      console.log((idx + 1) + '. [' + ap.name + '] MAC: ' + ap.mac);
      console.log('   - Download: ' + (ap.rx / (1024 * 1024)).toFixed(2) + ' MB (' + ap.rx.toLocaleString() + ' Bytes)');
      console.log('   - Upload:   ' + (ap.tx / (1024 * 1024)).toFixed(2) + ' MB (' + ap.tx.toLocaleString() + ' Bytes)');
      console.log('   - Tổng:     ' + (apTotal / (1024 * 1024)).toFixed(2) + ' MB');
    });
  });
}).on('error', function(e) {
  console.error('Lỗi kết nối tới collector:', e.message);
});
