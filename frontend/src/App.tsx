import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'
import Layout from '@/components/layout/Layout'
import LoginPage from '@/pages/LoginPage'
import DashboardPage from '@/pages/DashboardPage'
import PRReviewsListPage from '@/pages/PRReviewsListPage'
import PRReviewPage from '@/pages/PRReviewPage'
import SecurityPage from '@/pages/SecurityPage'
import QualityPage from '@/pages/QualityPage'
import RepositoriesPage from '@/pages/RepositoriesPage'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token)
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="reviews" element={<PRReviewsListPage />} />
          <Route path="reviews/:reviewId" element={<PRReviewPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="quality" element={<QualityPage />} />
          <Route path="repositories" element={<RepositoriesPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
