const http = require('http');

const userData = {
  name: 'Ali',
  age: 25,
  is_admin: true
};

const jsonData = JSON.stringify(userData);

const options = {
  hostname: 'localhost',
  port: 5000,
  path: '/api/user',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(jsonData)
  }
};

const req = http.request(options, res => {
  let responseData = '';

  res.on('data', chunk => {
    responseData += chunk;
  });

  res.on('end', () => {
    console.log('Server Response:', responseData);
  });
});

req.on('error', error => {
  console.error('Error:', error);
});

req.write(jsonData);
req.end();
