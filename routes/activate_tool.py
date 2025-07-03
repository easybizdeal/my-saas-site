{% extends "base.html" %}
{% block title %}Tool Activated – Easy Biz Deal{% endblock %}
{% block content %}
<style>
  .popup-container {
    max-width: 600px;
    margin: 100px auto;
    background: white;
    padding: 40px;
    text-align: center;
    border-radius: 16px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
    font-family: 'Segoe UI', sans-serif;
  }

  .popup-container h2 {
    color: #10b981;
    font-size: 24px;
    margin-bottom: 15px;
  }

  .popup-container p {
    font-size: 16px;
    color: #374151;
    margin-bottom: 30px;
  }

  .popup-container .btn-group a {
    display: inline-block;
    margin: 0 10px;
    padding: 12px 20px;
    border-radius: 8px;
    text-decoration: none;
    color: white;
    background: #3b82f6;
    transition: 0.3s;
  }

  .popup-container .btn-group a:hover {
    background: #2563eb;
  }
</style>

<div class="popup-container">
  <h2>Tool Activated!</h2>
  <p>This tool has been added to your Tools Dashboard.</p>
  <div class="btn-group">
    <a href="/dashboard">Back to Dashboard</a>
    <a href="/tools-dashboard">Go to Tools Dashboard</a>
  </div>
</div>
{% endblock %}
