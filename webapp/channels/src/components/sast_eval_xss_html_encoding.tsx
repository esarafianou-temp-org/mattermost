// SAST EVALUATION COMPONENT - CWE-79 (Cross-Site Scripting) - HTML Encoding Limitation
// WARNING: This component contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

import React from 'react';

interface Props {
    userColor: string; // Simulates untrusted user input (e.g., color preference from API)
    userTheme: string; // Simulates untrusted user input (e.g., theme name from form)
}

/**
 * HTML Entity Encoding utility - appears to be a security measure
 * but is insufficient for attribute context XSS prevention
 */
function htmlEncode(input: string): string {
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

/**
 * SECURITY VULNERABILITY - CWE-79: Cross-Site Scripting (XSS)
 * Context-Sensitive XSS in Unquoted HTML Attributes
 * 
 * This component demonstrates a subtle XSS vulnerability where HTML encoding
 * is applied (which might make SAST tools think the data is safe), but the
 * encoded data is still vulnerable when used in unquoted HTML attribute contexts.
 * 
 * Attack Vector Examples:
 * userColor = "red onmouseover=alert('XSS')" 
 * userTheme = "dark onclick=alert(document.cookie) x"
 * 
 * Even after HTML encoding, these payloads can execute JavaScript because:
 * 1. Spaces are not encoded by basic HTML encoding
 * 2. Unquoted attributes allow space-separated values to be interpreted as new attributes
 * 3. Event handlers in the new attributes execute JavaScript
 * 
 * VULNERABILITY: HTML encoding insufficient for unquoted attribute context
 * FIX: Use quoted attributes AND proper attribute encoding, or use React's 
 * built-in props which automatically handle attribute context safely
 */
export const SastEvalXSSHtmlEncoding: React.FC<Props> = ({userColor, userTheme}) => {
    // Apply HTML encoding - this looks like a security measure but is insufficient
    const encodedColor = htmlEncode(userColor);
    const encodedTheme = htmlEncode(userTheme);

    return (
        <div>
            <h3>User Theme Preview</h3>
            {/* VULNERABLE CODE: HTML encoded data in unquoted attributes */}
            <div 
                className="theme-preview"
                dangerouslySetInnerHTML={{
                    __html: `
                        <div style=color:${encodedColor} class=${encodedTheme}>
                            Themed content with user preferences
                        </div>
                        <button style=background-color:${encodedColor} onclick="alert('Safe click')">
                            Apply Theme
                        </button>
                    `
                }}
            />
            
            {/* Additional vulnerability: Template literal with unquoted attributes */}
            <div 
                dangerouslySetInnerHTML={{
                    __html: `<span title=${encodedTheme} style=color:${encodedColor}>Hover for theme info</span>`
                }}
            />
        </div>
    );
};

// Example of safer implementation (commented out):
// export const SafeThemeDisplay: React.FC<Props> = ({userColor, userTheme}) => {
//     return (
//         <div>
//             <h3>User Theme Preview</h3>
//             {/* SAFER: React handles attribute context automatically */}
//             <div 
//                 className="theme-preview"
//                 style={{color: userColor}} // React properly escapes style values
//                 data-theme={userTheme}     // React properly escapes attribute values
//             >
//                 Themed content with user preferences
//             </div>
//         </div>
//     );
// };