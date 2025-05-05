import React, { useEffect, useState } from 'react';
//import { Button } from '@/components/ui/button';  //These are causing errors, likely because the components are not defined.  I've replaced them with standard HTML button.
//import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'; //These are causing errors.  I've replaced them with standard divs.
//import { Badge } from '@/components/ui/badge';  //This is causing errors. I've replaced it with a span.
//import { cn } from '@/lib/utils'; //This is not used, so I'm removing it.

// Add Chrome types
declare global {
  namespace chrome {
    namespace tabs {
      interface Tab {
        url?: string;
      }
      function query(queryInfo: { active: boolean; currentWindow: boolean }, callback: (tabs: Tab[]) => void): void;
    }
  }
}

// Replace with your NVD API key if you have one (optional, for higher rate limits)
const NVD_API_KEY = '';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// Mock function to simulate identifying software on a website.
// In a real extension, this would involve more complex logic.
const identifySoftware = async (url: string): Promise<string[]> => {
  // Simulate network delay
  await new Promise((resolve) => setTimeout(resolve, 500));

  if (url.includes('wordpress')) {
    return ['wordpress'];
  } else if (url.includes('joomla')) {
    return ['joomla'];
  } else if (url.includes('drupal')) {
    return ['drupal'];
  } else if (url.includes('reactjs')) {
    return ['react'];
  } else {
    return ['generic-website'];
  }
};

const fetchNvdData = async (software: string): Promise<any[]> => {
  const query = `keyword=${encodeURIComponent(software)}`;
  const apiKeyParam = NVD_API_KEY ? `apiKey=${NVD_API_KEY}&` : '';
  const url = `${NVD_BASE_URL}?${apiKeyParam}${query}`;

  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`NVD API error: ${response.status}`);
    }
    const data = await response.json();
    return data.vulnerabilities || []; // Returns an empty array if no vulnerabilities
  } catch (error: any) {
    console.error('Error fetching NVD data:', error);
    return [];
  }
};

const getSeverityBadge = (cvssV3Severity: string) => {
    let badgeColor = '';
    switch (cvssV3Severity) {
        case 'CRITICAL':
            badgeColor = 'bg-red-600 text-white';
            break;
        case 'HIGH':
            badgeColor = 'bg-red-500 text-white';
            break;
        case 'MEDIUM':
            badgeColor = 'bg-yellow-500 text-gray-900';
            break;
        case 'LOW':
            badgeColor = 'bg-gray-400 text-gray-900';
            break;
        default:
            badgeColor = 'bg-gray-200 text-gray-900';
    }
  return <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${badgeColor} capitalize`}>{cvssV3Severity}</span>;
};

const VulnerabilityCard = ({ vulnerability }: { vulnerability: any }) => {
  const cve = vulnerability.cve;
  const cvssV3 = cve.metrics?.cvssMetricV31?.[0];

  return (
    <div className="border rounded-md p-4 mb-4 bg-white/5 backdrop-blur-md border-white/10">
      <h3 className="text-lg font-semibold text-white">{cve.id}</h3>
      <p className="text-gray-400 mb-2">{cve.descriptions?.[0]?.value || 'No description available.'}</p>

      {cvssV3 && (
        <div className="flex items-center gap-2 mb-2">
          <span className="text-sm font-medium text-gray-300">Severity:</span>
          {getSeverityBadge(cvssV3.cvssV3.baseSeverity)}
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {cve.references?.map((ref: any, index: number) => (
          <a
            key={index}
            href={ref.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 hover:text-blue-300 hover:underline text-sm"
          >
            Reference {index + 1}
          </a>
        ))}
      </div>
    </div>
  );
};

const NVDSecurityChecker = () => {
  const [currentURL, setCurrentURL] = useState('');
  const [softwareList, setSoftwareList] = useState<string[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanCompleted, setScanCompleted] = useState(false);

  useEffect(() => {
    //  Get the current tab's URL.  This is the key part that makes
    //  it work as a Chrome extension.
    if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.url) {
          setCurrentURL(tabs[0].url);
        }
      });
    } else {
      //  This is for testing in a regular browser environment.
      //  It won't work in a real extension.
      setCurrentURL(window.location.href);
    }
  }, []);

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    setVulnerabilities([]);
    setScanCompleted(false);

    try {
      const software = await identifySoftware(currentURL);
      setSoftwareList(software);
      console.log('Identified software:', software);

      let allVulnerabilities: any[] = [];
      for (const soft of software) {
        const softVulnerabilities = await fetchNvdData(soft);
        allVulnerabilities = allVulnerabilities.concat(softVulnerabilities);
      }
      setVulnerabilities(allVulnerabilities);
    } catch (err: any) {
      setError(err.message || 'An error occurred during the scan.');
    } finally {
      setLoading(false);
      setScanCompleted(true);
    }
  };

  const noVulnerabilitiesFound = scanCompleted && vulnerabilities.length === 0 && !error;

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-black p-4 md:p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl md:text-4xl font-bold text-center text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-400 mb-6 md:mb-8">
          NVD Security Checker
        </h1>

        <div className="bg-white/5 backdrop-blur-md rounded-lg p-4 md:p-6 mb-6 border border-white/10">
          <p className="text-gray-400 text-sm mb-2">Current URL:</p>
          <p className="text-white font-medium truncate">{currentURL}</p>
        </div>

        <div className="flex justify-center mb-6">
          <button
            onClick={handleScan}
            disabled={loading}
            className='bg-gradient-to-r from-blue-500 to-purple-500 text-white px-6 py-3 rounded-full hover:from-blue-600 hover:to-purple-600 transition-all duration-300 shadow-lg hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2'
          >
            {loading ? (
              <>
                <span className="animate-spin inline-block w-5 h-5 border-2 border-white border-t-transparent rounded-full"></span>
                Scanning...
              </>
            ) : (
              'Scan for Vulnerabilities'
            )}
          </button>
        </div>

        {error && (
          <div className="mb-6 bg-red-500/10 border border-red-500/20 text-red-400 rounded-md p-4 flex items-start gap-2">
            <span className="text-red-400 text-xl">⚠️</span>
            <div>
              <h2 className="text-lg font-semibold">Error</h2>
              <p>{error}</p>
            </div>
          </div>
        )}

        {loading && (
          <div className="text-center text-gray-400">
            <span className="animate-spin inline-block w-8 h-8 border-2 border-gray-400 border-t-transparent rounded-full mb-4"></span>
            <p>Scanning for vulnerabilities...</p>
          </div>
        )}

        {noVulnerabilitiesFound && (
          <div className="mb-6 bg-green-500/10 border border-green-500/20 text-green-400 rounded-md p-4 flex items-start gap-2">
            <span className="text-green-400 text-xl">✓</span>
            <div>
              <h2 className="text-lg font-semibold">No Vulnerabilities Found</h2>
              <p>
                Great news! No known vulnerabilities were found for the software detected on this website.
              </p>
            </div>
          </div>
        )}

        {!loading && !error && scanCompleted && vulnerabilities.length > 0 && (
          <div className="bg-white/5 backdrop-blur-md rounded-lg p-4 md:p-6 border border-white/10">
            <h2 className="text-2xl font-semibold text-white mb-4">Vulnerabilities Found:</h2>
            {vulnerabilities.map((vulnerability: any, index: number) => (
              <VulnerabilityCard key={index} vulnerability={vulnerability} />
            ))}
          </div>
        )}
        {!loading && !error && scanCompleted && softwareList.length > 0 && vulnerabilities.length === 0 && (
          <div className="bg-white/5 backdrop-blur-md rounded-lg p-4 md:p-6 border border-white/10">
            <h2 className="text-2xl font-semibold text-white mb-4">No Vulnerabilities Found:</h2>
            <p className="text-gray-400">No vulnerabilities found for the detected software.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default NVDSecurityChecker;