import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from './app/query-client';
import { App } from './App';
import './styles.css';
createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><QueryClientProvider client={queryClient}><App /></QueryClientProvider></BrowserRouter></React.StrictMode>);
