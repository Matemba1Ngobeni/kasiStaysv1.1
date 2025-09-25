
import React, { useState } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Header from './components/Header';
import Hero from './components/Hero';
import ListingsGrid from './components/ListingsGrid';
import ProvidersGrid from './components/ProvidersGrid';
import AuthModal from './components/AuthModal';
import Dashboard from './components/Dashboard';
import { Lucide } from './components/Lucide';

const AppContent: React.FC = () => {
    const { userProfile, loading } = useAuth();
    const [isAuthModalOpen, setAuthModalOpen] = useState(false);
    const [authModalView, setAuthModalView] = useState<'signIn' | 'signUp'>('signIn');
    const [isDashboardView, setDashboardView] = useState(false);

    const openModal = (view: 'signIn' | 'signUp') => {
        setAuthModalView(view);
        setAuthModalOpen(true);
    };

    const closeModal = () => {
        setAuthModalOpen(false);
    };
    
    // Automatically switch to dashboard view on login if it's not already active
    React.useEffect(() => {
        if (userProfile && !isDashboardView) {
            setDashboardView(true);
        }
        if (!userProfile) {
            setDashboardView(false);
        }
    }, [userProfile]);

    return (
        <div className="min-h-screen flex flex-col">
            <Header 
                onSignInClick={() => openModal('signIn')} 
                onSignUpClick={() => openModal('signUp')}
                onDashboardClick={() => setDashboardView(true)}
                onHomeClick={() => setDashboardView(false)}
            />
            <main className="flex-grow container mx-auto px-4 py-8">
                {loading ? (
                    <div className="flex justify-center items-center h-64">
                        <div className="loader"></div>
                    </div>
                ) : userProfile && isDashboardView ? (
                    <Dashboard userProfile={userProfile} />
                ) : (
                    <>
                        <Hero />
                        <ListingsGrid />
                        <ProvidersGrid />
                    </>
                )}
            </main>
            <footer className="bg-white border-t">
                <div className="container mx-auto px-4 py-6 text-center text-gray-600">
                    &copy; {new Date().getFullYear()} KasiStays. All rights reserved.
                </div>
            </footer>
            {isAuthModalOpen && (
                <AuthModal
                    initialView={authModalView}
                    onClose={closeModal}
                />
            )}
            <Lucide />
        </div>
    );
};


const App: React.FC = () => {
    return (
        <AuthProvider>
            <AppContent />
        </AuthProvider>
    );
}

export default App;
