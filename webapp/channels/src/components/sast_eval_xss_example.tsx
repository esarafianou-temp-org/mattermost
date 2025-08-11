// SAST EVALUATION COMPONENT - CWE-79 (Cross-Site Scripting)
// WARNING: This component contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

import React from 'react';

interface Props {
    userMessage: string; // Simulates untrusted user input from API/form
}

/**
 * SECURITY VULNERABILITY - CWE-79: Cross-Site Scripting (XSS)
 * 
 * This component demonstrates a DOM-based XSS vulnerability by directly
 * inserting unsanitized user input into the DOM using dangerouslySetInnerHTML.
 * 
 * Attack Vector: If userMessage contains malicious JavaScript like:
 * '<script>alert("XSS")</script>' or '<img src=x onerror="alert(document.cookie)">'
 * it will be executed in the user's browser.
 * 
 * VULNERABILITY: User-controlled data is rendered without sanitization
 * FIX: Use React's built-in XSS protection by removing dangerouslySetInnerHTML
 * or sanitize the HTML using a library like DOMPurify
 */
export const SastEvalXSSExample: React.FC<Props> = ({userMessage}) => {
    return (
        <div>
            <h3>User Message Preview</h3>
            {/* VULNERABLE CODE: Direct HTML injection without sanitization */}
            <div 
                className="user-message-content"
                dangerouslySetInnerHTML={{__html: userMessage}}
            />
        </div>
    );
};

// Example of safe implementation (commented out):
// export const SafeMessageDisplay: React.FC<Props> = ({userMessage}) => {
//     return (
//         <div>
//             <h3>User Message Preview</h3>
//             {/* SAFE: React automatically escapes content */}
//             <div className="user-message-content">
//                 {userMessage}
//             </div>
//         </div>
//     );
// };