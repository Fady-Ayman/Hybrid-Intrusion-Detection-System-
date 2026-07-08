import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import PrivateRoute from './components/PrivateRoute';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Network from './pages/Network';
import Logs from './pages/Logs';
import PCAPAnalysis from './pages/PCAPAnalysis';
import Login from './pages/Login';


function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          
          <Route path="/*" element={
            <PrivateRoute />
          }>
            <Route path="*" element={
              <div className="flex min-h-screen bg-slate-950">
                <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen(!sidebarOpen)} />
                <main className={`flex-1 transition-all duration-300 ${sidebarOpen ? 'ml-64' : 'ml-20'}`}>
                  <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/alerts" element={<Alerts />} />
                    <Route path="/network" element={<Network />} />
                    <Route path="/pcap" element={<PCAPAnalysis />} />
                    
                    
                    {/* Admin Only Routes */}
                    <Route element={<PrivateRoute requiredRole="admin" />}>
                      <Route path="/logs" element={<Logs />} />
                    </Route>
                  </Routes>
                </main>
              </div>
            } />
          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
