const express = require('express');
const app = express();
const port = 5000;

// Middleware to parse JSON
app.use(express.json());

app.post('/api/user', (req, res) => {
  const { name, age, is_admin } = req.body;

  console.log(`Received user: ${name}, Age: ${age}, Admin: ${is_admin}`);

  res.json({
    status: 'success',
    message: `Hello ${name}, your data was received!`
  });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
