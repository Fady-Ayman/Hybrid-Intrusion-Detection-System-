export const API_BASE_URL = 'http://localhost:8000/api';

export const fetchSystemInfo = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/system/info`, { credentials: 'include' });
    if (!response.ok) throw new Error('Network response was not ok');
    return await response.json();
  } catch (error) {
    console.error('Failed to fetch system info:', error);
    return null;
  }
};

export const fetchDashboardStats = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/dashboard/stats`, { credentials: 'include' });
    if (!response.ok) throw new Error('Network response was not ok');
    return await response.json();
  } catch (error) {
    console.error('Failed to fetch dashboard stats:', error);
    return null;
  }
};
