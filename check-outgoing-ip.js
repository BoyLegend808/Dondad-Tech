const https = require('https');

function getIP(callback) {
  https.get('https://api.ipify.org?format=json', (resp) => {
    let data = '';
    resp.on('data', (chunk) => {
      data += chunk;
    });
    resp.on('end', () => {
      try {
        const ip = JSON.parse(data).ip;
        callback(null, ip);
      } catch (e) {
        callback(e);
      }
    });
  }).on("error", (err) => {
    callback(err);
  });
}

getIP((err, ip) => {
  if (err) {
    console.error('Error getting IP:', err);
    // Try alternative service
    https.get('https://ifconfig.me/ip', (resp) => {
      let data = '';
      resp.on('data', (chunk) => {
        data += chunk;
      });
      resp.on('end', () => {
        const ip = data.trim();
        console.log('Alternative service IP:', ip);
      });
    }).on("error", (err2) => {
      console.error('Alternative service also failed:', err2);
    });
  } else {
    console.log('Your outgoing IP is:', ip);
    console.log('Please ensure this IP is whitelisted in MongoDB Atlas');
  }
});