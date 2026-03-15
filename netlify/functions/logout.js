// Netlify Serverless Function - Logout
// This replaces the /api/logout endpoint for Netlify deployment

exports.handler = async (event, context) => {
  // Only allow POST
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: false, error: 'Method not allowed' })
    };
  }

  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // For logout, we just return success - the client handles clearing tokens
  // In a full implementation, you'd invalidate the token server-side
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ success: true, message: 'Logged out successfully' })
  };
};