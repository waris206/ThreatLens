import { useState } from 'react';
import AdminLogin from './AdminLogin';
import AdminDashboard from './AdminDashboard';

const AdminPortal = ({ onClose }) => {
  const [adminKey, setAdminKey] = useState(() => sessionStorage.getItem('threatlens_admin_key') || '');

  const handleAuthenticated = (key) => {
    sessionStorage.setItem('threatlens_admin_key', key);
    setAdminKey(key);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/95 backdrop-blur-sm">
      {adminKey ? (
        <AdminDashboard adminKey={adminKey} onClose={onClose} />
      ) : (
        <AdminLogin onAuthenticated={handleAuthenticated} onClose={onClose} />
      )}
    </div>
  );
};

export default AdminPortal;
