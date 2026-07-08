import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  AlertTriangle,
  Network,
  FileText,
  Database,
  Info,
  ChevronLeft,
  ChevronRight,
  Lock
} from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  onToggle: () => void;
}

const menuItems = [
  { path: '/', icon: LayoutDashboard, label: 'Overview' },
  { path: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { path: '/network', icon: Network, label: 'Network' },
  { path: '/logs', icon: FileText, label: 'Logs' },
  { path: '/pcap', icon: Database, label: 'PCAP Analysis' },
];

export default function Sidebar({ isOpen, onToggle }: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, setUser } = useAuth();
  
  const handleLogout = async () => {
    try {
      await fetch('http://localhost:8000/api/logout', { method: 'POST', credentials: 'include' });
      setUser(null);
      navigate('/login');
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <aside
      className={`fixed left-0 top-0 h-full bg-slate-900/95 backdrop-blur-xl border-r border-cyan-500/20 transition-all duration-300 z-50 ${
        isOpen ? 'w-64' : 'w-20'
      }`}
    >
      {/* Logo */}
      <div className="flex items-center justify-between h-20 px-4 border-b border-cyan-500/20 overflow-hidden relative">
        <div className={`flex items-center h-full w-full ${isOpen ? 'justify-center' : 'justify-start'}`}>
          <img 
            src="/logo.png" 
            alt="Logo" 
            className={`transition-all duration-300 ${isOpen ? 'w-full h-full object-contain scale-[2.5] object-center' : 'w-10 h-10 object-cover object-left'}`} 
          />
        </div>
        <button
          onClick={onToggle}
          className="absolute right-2 p-2 rounded-lg bg-slate-900/60 backdrop-blur-md hover:bg-slate-800 text-gray-400 hover:text-cyan-400 transition-colors z-10"
        >
          {isOpen ? <ChevronLeft size={20} /> : <ChevronRight size={20} />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="p-4 space-y-2 flex-1 overflow-y-auto">
        {menuItems.map((item) => {
          // RBAC Restrictions
          if (item.path === '/logs' && user?.role !== 'admin') return null;

          const Icon = item.icon;
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-500/20 to-cyan-600/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-gray-400 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <Icon
                size={20}
                className={`${
                  isActive ? 'text-cyan-400' : 'text-gray-500 group-hover:text-cyan-400'
                } transition-colors`}
              />
              {isOpen && (
                <span className="font-medium tracking-wide">{item.label}</span>
              )}
              {isActive && isOpen && (
                <div className="ml-auto w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Status Footer */}
      <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-cyan-500/20 bg-slate-900/95">
        <div className={`flex items-center gap-3 ${isOpen ? 'justify-between' : 'justify-center'}`}>
          <div className="flex items-center gap-2">
            <Lock size={16} className="text-green-400" />
            {isOpen && (
              <div>
                <p className="text-xs text-gray-400">{user?.username}</p>
                <p className="text-sm text-green-400 font-semibold">{user?.role?.toUpperCase()}</p>
              </div>
            )}
          </div>
          {isOpen && (
            <button 
              onClick={handleLogout}
              className="text-xs px-2 py-1 bg-red-500/10 text-red-400 rounded hover:bg-red-500/20 transition-colors"
            >
              Logout
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}
