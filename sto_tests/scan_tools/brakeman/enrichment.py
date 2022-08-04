#
#  ZeroNorth Gauss Issue Normalization Service
#
#  Copyright (C) 2015-2020 ZeroNorth, Inc. All Rights Reserved.
#
#  All information, in plain text or obfuscated form, contained herein
#  is, and remains the property of ZeroNorth, Inc. and its suppliers, if any.
#  The intellectual and technical concepts contained
#  herein are proprietary to ZeroNorth, Inc. and its suppliers
#  and may be covered by U.S. and Foreign Patents,
#  patents in process, and are protected by trade secret or copyright law.
#
#  Dissemination of this information or reproduction of this material
#  is strictly forbidden unless prior written permission is obtained
#  from ZeroNorth, Inc. (support@zeronorth.io)
#
#  https://www.zeronorth.io
#
# flake8: noqa
items = {}

items["attribute_restriction"] = {
    "description": """
    <header>
        <h1 class="entry-title">Attribute Restriction</h1>
    </header>
    
    <p>This warning type only applies to Ruby on Rails applications which are not using <a href="https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters">strong parameters</a>.</p>

    <p>Note that disabling mass assignment globally will suppress these warnings.</p>

    <h4 id="missing-protection">Missing Protection</h4>

    <p>This warning comes up if a model does not limit what attributes can be set through <a href="https://guides.rubyonrails.org/v3.2.9/security.html#mass-assignment">mass assignment</a>.</p>

    <p>In particular, this check looks for <code class="highlighter-rouge">attr_accessible</code> inside model definitions. If it is not found, this warning will be issued.</p>

    <h4 id="use-of-blacklist">Use of Blacklist</h4>

    <p>Brakeman also warns on use of <code class="highlighter-rouge">attr_protected</code> - especially since it was found to be <a href="https://groups.google.com/d/topic/rubyonrails-security/AFBKNY7VSH8/discussion">vulnerable to bypass</a>. Warnings for mass assignment on models using <code class="highlighter-rouge">attr_protected</code> will be reported, but at a lower confidence level.</p>

    <h4 id="suggested-remediation">Suggested Remediation</h4>

    <p>For newer Ruby on Rails applications, query parameters should be whitelisted before use via strong parameters.</p>

    <p>For older Ruby on Rails applications, each model should use <code class="highlighter-rouge">attr_accessible</code> to carefully whitelist which attributes may be set via mass assignment, if any.</p>
    """
}

items["authentication"] = {
    "description": """
    <header>
        <h1 class="entry-title">Authentication</h1>
    </header>
    
    <p>“Authentication” is the act of verifying that a user or client is who they say they are.</p>

    <p>Right now, the only Brakeman warning in the authentication category is regarding hardcoded passwords.
    Brakeman will warn about constants with literal string values that appear to be passwords.</p>

    <p>Hardcoded passwords are security issues since they imply a single password and that password is stored in the source code.
    Typically source code is available to a wide number of people inside an organization, and there have been many instances of source
    code leaking to the public. Passwords and secrets should be stored in a separate, secure location to limit access.</p>

    <p>Additionally, it is recommended not to use a single password for accessing sensitive information.
    Each user should have their own password to make it easier to audit and revoke access.</p>
    """
}

items["basic_authentication"] = {
    "description": """
    <header>
    <h1 class="entry-title">Basic Authentication</h1>
    </header>

    <p>In Rails 3.1, a new feature was added to simplify basic authentication.</p>

    <p>The example provided in the official <a href="http://guides.rubyonrails.org/getting_started.html">Rails Guide</a> looks like this:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>class PostsController &lt; ApplicationController

    http_basic_authenticate_with :name =&gt; "dhh", :password =&gt; "secret", :except =&gt; :index

    #...

    end
    </code></pre></div></div>

    <p>This warning will be raised if <code class="highlighter-rouge">http_basic_authenticate_with</code> is used and the password is found to be a string (i.e., stored somewhere in the code).</p>
    """
}

items["command_injection"] = {
    "description": """
    <header>
    <h1 class="entry-title">Command Injection</h1>
    </header>

    <p>Injection is #1 on the 2010 <a href="https://www.owasp.org/index.php/Top_10_2010-A1">OWASP Top Ten</a> web security risks. Command injection occurs when shell commands unsafely include user-manipulatable values.</p>

    <p>There are many ways to run commands in Ruby:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>`ls #{params[:file]}`

    system("ls #{params[:dir]}")

    exec("md5sum #{params[:input]}")
    </code></pre></div></div>

    <p>Brakeman will warn on any method like these that uses user input or unsafely interpolates variables.</p>

    <p>See <a href="http://guides.rubyonrails.org/security.html#command-line-injection">the Ruby Security Guide</a> for details.</p>
    """
}

items["cross-site_request_forgery"] = {
    "description": """        
    <header>
    <h1 class="entry-title">Cross Site Request Forgery</h1>
    </header>

    <p>Cross-site request forgery is #5 on the <a href="https://www.owasp.org/index.php/Top_10_2010-A5">OWASP Top Ten</a>. CSRF allows an attacker to perform actions on a website as if they are an authenticated user.</p>

    <p>This warning is raised when no call to <code class="highlighter-rouge">protect_from_forgery</code> is found in <code class="highlighter-rouge">ApplicationController</code>. This method prevents CSRF.</p>

    <p>For Rails 4 applications, it is recommended that you use <code class="highlighter-rouge">protect_from_forgery :with =&gt; :exception</code>. This code is inserted into newly generated applications. The default is to <code class="highlighter-rouge">nil</code> out the session object, which has been a source of many CSRF bypasses due to session memoization.</p>

    <p>See <a href="http://guides.rubyonrails.org/security.html#cross-site-request-forgery-csrf">the Ruby Security Guide</a> for details.</p>
    """
}

items["cross_site_scripting"] = {
    "description": """        
    <header>
    <h1 class="entry-title">Cross Site Scripting</h1>
    </header>

    <p>Cross site scripting (or XSS) is #2 on the 2010 <a href="https://www.owasp.org/index.php/Top_10_2010-A2">OWASP Top Ten</a> web security risks and it pops up nearly everywhere.</p>

    <p>XSS occurs when a user-manipulatable value is displayed on a web page without escaping it, allowing someone to inject Javascript or HTML into the page.</p>

    <p>In Rails 2.x, values need to be explicitly escaped (e.g., by using the <code class="highlighter-rouge">h</code> method). In Rails 3.x, auto-escaping in views is enabled by default. However, one can still use the <code class="highlighter-rouge">raw</code> method to output a value directly.</p>

    <p>See <a href="http://guides.rubyonrails.org/security.html#cross-site-scripting-xss">the Ruby Security Guide</a> for more details.</p>

    <h3 id="query-parameters-and-cookies">Query Parameters and Cookies</h3>

    <p>Rails 2.x example in ERB:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&lt;%= params[:query] %&gt;
    </code></pre></div></div>

    <p>Brakeman looks for several situations that can allow XSS. The simplest is like the example above: a value from the <code class="highlighter-rouge">params</code> or <code class="highlighter-rouge">cookies</code> is being directly output to a view. In such cases, it will issue a warning like:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Unescaped parameter value near line 3: params[:query]
    </code></pre></div></div>

    <p>By default, Brakeman will also warn when a parameter or cookie value is used as an argument to a method, the result of which is output unescaped to a view.</p>

    <p>For example:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&lt;%= some_method(cookie[:name]) %&gt;
    </code></pre></div></div>

    <p>This raises a warning like:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Unescaped cookie value near line 5: some_method(cookies[:oreo])
    </code></pre></div></div>

    <p>However, the confidence level for this warning will be weak, because it is not directly outputting the cookie value.</p>

    <p>Some methods are known to Brakeman to either be dangerous (<code class="highlighter-rouge">link_to</code> is one) or safe (<code class="highlighter-rouge">escape_once</code>). Users can specify safe methods using the <code class="highlighter-rouge">--safe-methods</code> option. Alternatively, Brakeman can be set to <em>only</em> warn when values are used directly with the <code class="highlighter-rouge">--report-direct</code> option.</p>

    <h3 id="model-attributes">Model Attributes</h3>

    <p>Because (many) models come from database values, Brakeman mistrusts them by default.</p>

    <p>For example, if <code class="highlighter-rouge">@user</code> is an instance of a model set in an action like</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>def set_user
    @user = User.first
    end
    </code></pre></div></div>

    <p>and there is a view with</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&lt;%= @user.name %&gt;
    </code></pre></div></div>

    <p>Brakeman will raise a warning like</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Unescaped model attribute near line 3: User.first.name
    </code></pre></div></div>

    <p>If you trust all your data (although you probably shouldn’t), this can be disabled with <code class="highlighter-rouge">--ignore-model-output</code>.</p>
    """
}

items["content_tag"] = {
    "description": """        
    <header>
    <h1 class="entry-title">Cross Site Scripting (Content Tag)</h1>
    </header>

    <p>Cross site scripting (or XSS) is #2 on the 2010 <a href="https://www.owasp.org/index.php/Top_10_2010-A2">OWASP Top Ten</a> web security risks and it pops up nearly everywhere. XSS occurs when a user-manipulatable value is displayed on a web page without escaping it, allowing someone to inject Javascript or HTML into the page.</p>

    <p><a href="http://apidock.com/rails/ActionView/Helpers/TagHelper/content_tag">content_tag</a> is a view helper which generates an HTML tag with some content:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&gt;&gt; content_tag :p, "Hi!"
    =&gt; "&lt;p&gt;Hi!&lt;/p&gt;"
    </code></pre></div></div>

    <p>In Rails 2, this content is unescaped (although attribute values are escaped):</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&gt;&gt; content_tag :p, "&lt;script&gt;alert(1)&lt;/script&gt;"
    =&gt; "&lt;p&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/p&gt;"
    </code></pre></div></div>

    <p>In Rails 3, the content is escaped. However, only the <em>content</em> and the tag attribute <em>values</em> are escaped. The tag and attribute names are never escaped in Rails 2 or 3.</p>

    <p>This is more dangerous than a typical method call because <code class="highlighter-rouge">content_tag</code> marks its output as “HTML safe”, meaning the <code class="highlighter-rouge">rails_xss</code> plugin and Rails 3 auto-escaping will not escape its output. Due to this, <code class="highlighter-rouge">content_tag</code> should be used carefully if user input is provided as an argument.</p>

    <p>Note that while <code class="highlighter-rouge">content_tag</code> does have an <code class="highlighter-rouge">escape</code> parameter, this only applies to tag attribute <em>values</em> and is true by default.</p>
    """
}

items["cross_site_scripting_to_json"] = {
    "description": """        
    <header>
    <h1 class="entry-title">Cross Site Scripting (JSON)</h1>
    </header>

    <p>Cross site scripting (or XSS) is #2 on the 2010 <a href="https://www.owasp.org/index.php/Top_10_2010-A2">OWASP Top Ten</a> web security risks and it pops up nearly everywhere.</p>

    <p>XSS occurs when a user-manipulatable value is displayed on a web page without escaping it, allowing someone to inject Javascript or HTML into the page.  Calls to <code class="highlighter-rouge">Hash#to_json</code> can be used to trigger XSS.  Brakeman will check to see if there are any calls to <code class="highlighter-rouge">Hash#to_json</code> with <code class="highlighter-rouge">ActiveSupport#escape_html_entities_in_json</code> set to false (or if you are running Rails &lt; 2.1.0 which did not have this functionality).</p>

    <p><code class="highlighter-rouge">ActiveSupport#escape_html_entities_in_json</code> was introduced in the “new_rails_defaults” initializer in Rails 2.1.0 which is set to <code class="highlighter-rouge">false</code> by default.  In Rails 3.0.0, <code class="highlighter-rouge">true</code> became the default setting.  Setting this value to <code class="highlighter-rouge">true</code> will automatically escape ‘&lt;’, ‘&gt;’, ‘&amp;’ which are commonly used to break out of code generated by a to_json call.</p>

    <p>See <a href="http://rubydoc.info/docs/rails/ActiveSupport/JSON/Encoding.escape_html_entities_in_json=">ActiveSupport#escape_html_entities_in_json</a> for more details.</p>

    <h3 id="exploiting-to_json">Exploiting to_json</h3>

    <p>Consider the following snippet of Rails 2.x ERB:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code># controller
    @attrs = {:email =&gt; 'some@email.com&lt;/script&gt;&lt;script&gt;alert(document.domain)//'}

    &lt;!-- view --&gt;
    &lt;script&gt;
    var attributes = &lt;%= @attrs.to_json %&gt;
    &lt;/script&gt;
    </code></pre></div></div>

    <p>Which generates the following html:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&lt;script&gt;
    var attributes = {"email":"some@email.com&lt;/script&gt;&lt;script&gt;alert(document.domain)//"}
    &lt;/script&gt;
    </code></pre></div></div>

    <p>While the generated Javascript appears valid, the browser parses the script tags first, so it sees something like this:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&lt;script&gt;
    var attributes = {"email":"some@email.com
    &lt;/script&gt;
    &lt;script&gt;
    alert(document.domain)//"}
    &lt;/script&gt;
    </code></pre></div></div>

    <p>The attribute assignment causes a Javascript error, but the alert triggers just fine!</p>

    <p>With <code class="highlighter-rouge">escape_html_entities_in_json = true</code>, you will receive the following innocuous output:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>&lt;script&gt;
    var attributes = {"email":"some@email.com\u003C/script\u003E\u003Cscript\u003Ealert(document.domain)//"}
    &lt;/script&gt;
    </code></pre></div></div>
    """
}

items["dangerous_eval"] = {
    "description": """        
    <header>
    <h1 class="entry-title">Dangerous Evaluation</h1>
    </header>

    <p>User input in an <code class="highlighter-rouge">eval</code> statement is VERY dangerous, so this will always raise a warning. Brakeman looks for calls to <code class="highlighter-rouge">eval</code>, <code class="highlighter-rouge">instance_eval</code>, <code class="highlighter-rouge">class_eval</code>, and <code class="highlighter-rouge">module_eval</code>.</p>
    """
}

items["dangerous_send"] = {
    "description": """      
    <header>
    <h1 class="entry-title">Dangerous Send</h1>
    </header>

    <p>Using unfiltered user data to select a Class or Method to be dynamically sent is dangerous.</p>

    <p>It is much safer to whitelist the desired target or method.</p>

    <p>Unsafe use of method:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>method = params[:method]
    @result = User.send(method.to_sym)
    </code></pre></div></div>

    <p>Safe:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>method = params[:method] == 1 ? :method_a : :method_b
    @result = User.send(method, *args)
    </code></pre></div></div>

    <p>Unsafe use of target:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code><span class="n">table</span> <span class="p">=</span> <span class="n">params</span><span class="p">[:</span><span class="n">table</span><span class="p">]</span>
    <span class="k">model</span> <span class="p">=</span> <span class="n">table</span><span class="p">.</span><span class="n">classify</span><span class="p">.</span><span class="n">constantize</span>
    <span class="p">@</span><span class="n">result</span> <span class="p">=</span> <span class="k">model</span><span class="p">.</span><span class="nf">send</span><span class="p">(:</span><span class="n">method</span><span class="p">)</span>
    </code></pre></div></div>

    <p>Safe:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>target = params[:target] == 1 ? Account : User
    @result = target.send(:method, *args)
    </code></pre></div></div>

    <p>Including user data in the arguments passed to an Object#send is safe, as long as the method can properly handle potentially bad data.</p>

    <p>Safe:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>args = params["args"] || []
    @result = User.send(:method, *args)
    </code></pre></div></div>
    """
}

items["default_routes"] = {
    "description": """      
    <header>
        <h1 class="entry-title">Default Routes</h1>
    </header>
    
    <p>The general default routes warning means there is a call to</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>#Rails 2.x
    map.connect ":controller/:action/:id"
    </code></pre></div></div>

    <p>or</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Rails 3.x
    match ':controller(/:action(/:id(.:format)))'
    </code></pre></div></div>

    <p>in <code class="highlighter-rouge">config/routes.rb</code>. This allows any public method on any controller to be called as an action.</p>

    <p>If this warning is reported for a particular controller, it means there is a route to that controller containing <code class="highlighter-rouge">:action</code>.</p>

    <p>Default routes can be dangerous if methods are made public which are not intended to be used as URLs or actions.</p>
    """
}

items["denial_of_service"] = {
    "description": """      
    <header>
        <h1 class="entry-title">Denial of Service</h1>
    </header>
    
    <p>Denial of Service (DoS) is any attack which causes a service to become unavailable for legitimate clients.</p>

    <p>For issues that Brakeman detects, this typically arises in the form of memory leaks. In particular, since Symbols are not garbage collected, creation of large numbers of Symbols could lead to a server running out of memory.</p>

    <p>Brakeman checks for instances of user input which is converted to a Symbol. When this is not restricted, an attacker could create an unlimited number of Symbols.</p>

    <p>The best approach is to simply never convert user-controlled input to a Symbol. If this cannot be avoided, use a whitelist of acceptable values.</p>

    <p>For example:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>valid_values = ["valid", "values", "here"]

    if valid_values.include? params[:value]
    symbolized = params[:value].to_sym
    end
    </code></pre></div></div>

    <p>However, Brakeman will still warn about this, because it cannot tell a valid guard expression has been used.</p>

    <p>Avoiding the warning itself becomes silly:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>valid_values.each do |v|
    if v == params[:value]
        symbolized = v.to_sym
        break
    end
    end ---
    </code></pre></div></div>
    """
}

items["dynamic_render_paths"] = {
    "description": """  
    <header>
    <h1 class="entry-title">Dynamic Render Path</h1>
    </header>

    <p>When a call to <code class="highlighter-rouge">render</code> uses a dynamically generated path, template name, file name, or action, there is the possibility that a user can access templates that should be restricted. The issue may be worse if those templates execute code or modify the database.</p>

    <p>This warning is shown whenever the path to be rendered is not a static string or symbol.</p>

    <p>These warnings are often false positives, however, because it can be difficult to manipulate Rails’ assumptions about paths to perform malicious behavior. Reports of dynamic render paths should be checked carefully to see if they can actually be manipulated maliciously by the user.</p>
    """
}

items["file_access"] = {
    "description": """
    <header>
    <h1 class="entry-title">File Access</h1>
    </header>

    <p>Using user input when accessing files (local or remote) will raise a warning in Brakeman.</p>

    <p>For example</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>File.open("/tmp/#{cookie[:file]}")
    </code></pre></div></div>

    <p>will raise an error like</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Cookie value used in file name near line 4: File.open("/tmp/#{cookie[:file]}")
    </code></pre></div></div>

    <p>This type of vulnerability can be used to access arbitrary files on a server (including <code class="highlighter-rouge">/etc/passwd</code>.</p>
    """
}

items["format_validation"] = {
    "description": """
    <header>
        <h1 class="entry-title">Format Validation</h1>
    </header>
    
    <p>Calls to <code class="highlighter-rouge">validates_format_of ..., :with =&gt; //</code> which do not use <code class="highlighter-rouge">\A</code> and <code class="highlighter-rouge">\z</code> as anchors will cause this warning. Using <code class="highlighter-rouge">^</code> and <code class="highlighter-rouge">$</code> is not sufficient, as they will only match up to a new line. This allows an attacker to put whatever malicious input they would like before or after a new line character.</p>

    <p>See <a href="http://guides.rubyonrails.org/security.html#regular-expressions">the Ruby Security Guide</a> for details.</p>
    """
}

items["information_disclosure"] = {
    "description": """
    <header>
    <h1 class="entry-title">Information Disclosure</h1>
    </header>

    <p>Also known as <a href="https://www.owasp.org/index.php/Information_Leakage">information leakage</a> or <a href="https://cwe.mitre.org/data/definitions/200.html">information exposure</a>, this vulnerability refers to system or internal information (such as debugging output, stack traces, error messages, etc.) which is displayed to an end user.</p>

    <p>For example, Rails provides detailed exception reports by default in the development environment, but it is turned off by default in production:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code># Full error reports are disabled
    config.consider_all_requests_local = false
    </code></pre></div></div>

    <p>Brakeman warns if this setting is <code class="highlighter-rouge">true</code> in production or there is a <code class="highlighter-rouge">show_detailed_exceptions?</code> method in a controller which does not return <code class="highlighter-rouge">false</code>.</p>
    """
}

items["cve-2011-0446"] = {
    "description": """
    <header>
    <h1 class="entry-title">Mail Link (CVE-2011-0446)</h1>
    </header>

    <p>Certain versions of Rails were vulnerable to a cross-site scripting vulnerability mail_to.</p>

    <p>Versions of Rails after 2.3.10 or 3.0.3 are not affected. Updating or removing the mail_to links is advised.</p>

    <p>For more details see <a href="https://groups.google.com/group/rubyonrails-security/browse_thread/thread/f02a48ede8315f81">CVE-2011-0446</a>.</p>
    """
}

items["mass_assignment"] = {
    "description": """
    <header>
        <h1 class="entry-title">Mass Assignment</h1>
    </header>
    
    <p>Mass assignment is a feature of Rails which allows an application to create a record from the values of a hash.</p>

    <p>Example:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>User.new(params[:user])
    </code></pre></div></div>

    <p>Unfortunately, if there is a user field called <code class="highlighter-rouge">admin</code> which controls administrator access, now any user can make themselves an administrator with a query like</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>?user[admin]=true
    </code></pre></div></div>

    <h3 id="rails-with-strong-parameters">Rails With Strong Parameters</h3>

    <p>In Rails 4 and newer, protection for mass assignment is on by default.</p>

    <p>Query parameters must be explicitly whitelisted via <code class="highlighter-rouge">permit</code> in order to be used in mass assignment:</p>

    <p>User.new(params.permit(:name, :password))</p>

    <p>Care should be taken to only whitelist values that are safe for a user (or attacker) to set. Foreign keys such as <code class="highlighter-rouge">account_id</code> are likely unsafe, allowing an attacker to manipulate records belonging to other accounts.</p>

    <p>Brakeman will warn on potentially dangerous attributes that are whitelisted.</p>

    <p>Brakeman will also warn about uses of <code class="highlighter-rouge">params.permit!</code>, since that allows everything.</p>

    <h3 id="rails-without-strong-parameters">Rails Without Strong Parameters</h3>

    <p>In older versions of Rails, <code class="highlighter-rouge">attr_accessible</code> and <code class="highlighter-rouge">attr_protected</code> can be used to limit mass assignment.
    However, Brakeman will warn unless <code class="highlighter-rouge">attr_accessible</code> is used, or mass assignment is completely disabled.</p>

    <p>There are two different mass assignment warnings which can arise. The first is when mass assignment actually occurs, such as the example above. This results in a warning like</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Unprotected mass assignment near line 61: User.new(params[:user])
    </code></pre></div></div>

    <p>The other warning is raised whenever a model is found which does not use <code class="highlighter-rouge">attr_accessible</code>. This produces generic warnings like</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Mass assignment is not restricted using attr_accessible
    </code></pre></div></div>

    <p>with a list of affected models.</p>

    <p>In Rails 3.1 and newer, mass assignment can easily be disabled:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>config.active_record.whitelist_attributes = true
    </code></pre></div></div>

    <p>Unfortunately, it can also easily be bypassed:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>User.new(params[:user], :without_protection =&gt; true)
    </code></pre></div></div>

    <p>Brakeman will warn on uses of <code class="highlighter-rouge">without_protection</code>.</p>

    <h3 id="more-information">More Information</h3>

    <p><a href="http://edgeguides.rubyonrails.org/action_controller_overview.html#strong-parameters">Strong Parameters in Rails Security Guide</a>
    <a href="http://guides.rubyonrails.org/v3.2.8/security.html#mass-assignment">Mass Assignment in Rails Security Guide</a></p>
    """
}

items["remote_code_execution"] = {
    "description": """
    <header>
        <h1 class="entry-title">Remote Code Execution</h1>
    </header>
    
    <p>Brakeman reports on several cases of remote code execution, in which a user is able to control and execute code in ways unintended by application authors.</p>

    <p>The obvious form of this is the use of <code class="highlighter-rouge">eval</code> with user input.</p>

    <p>However, Brakeman also reports on dangerous uses of <code class="highlighter-rouge">send</code>, <code class="highlighter-rouge">constantize</code>, and other methods which allow creation of arbitrary objects or calling of arbitrary methods.</p>
    """
}

items["remote_code_execution_yaml_load"] = {
    "description": """
    <header>
        <h1 class="entry-title">Remote Code Execution in YAML.Load</h1>
    </header>
    
    <p>As seen in <a href="https://groups.google.com/d/topic/rubyonrails-security/61bkgvnSGTQ/discussion">CVE-2013-0156</a>, calling <code class="highlighter-rouge">YAML.load</code> with user input can lead to remote execution of arbitrary code. (To see a real point-and-fire exploit, see the <a href="https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/rails_xml_yaml_code_exec.rb">Metasploit payload</a>). While upgrading Rails, disabling XML parsing, or disabling YAML types in XML request parsing will fix the Rails vulnerability, manually passing user input to <code class="highlighter-rouge">YAML.load</code> remains unsafe.</p>

    <p>For example:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>#Do not do this!
    YAML.load(params[:file])
    </code></pre></div></div>
    """
}

items["session_manipulation"] = {
    "description": """
    <header>
    <h1 class="entry-title">Session Manipulation</h1>
    </header>

    <p>Session manipulation can occur when an application allows user-input in session keys.
    Since sessions are typically considered a source of truth (e.g. to check the logged-in user or to match CSRF tokens),
    allowing an attacker to manipulate the session may lead to unintended behavior.</p>

    <p>For example:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>user_id = session[params[:name]]
    current_user = User.find(user_id)
    </code></pre></div></div>

    <p>In this scenario, the attacker can point the <code class="highlighter-rouge">name</code> parameter to some other session value (for example, <code class="highlighter-rouge">_csrf_token</code>) that will be interpreted
    as a user ID. If the ID matches an existing account, the attacker will now have access to that account.</p>

    <p>To prevent this type of session manipulation, avoid using user-supplied input as session keys.</p>

    <p>(<a href="https://gist.github.com/joernchen/9dfa57017b4732c04bcc">See here for a tiny, self-contained challenge demonstrating this issue</a>.)</p>
    """
}

items["sql_injection"] = {
    "description": """
    <header>
    <h1 class="entry-title">SQL Injection</h1>
    </header>

    <p>Injection is #1 on the 2010 <a href="https://www.owasp.org/index.php/Top_10_2010-A1">OWASP Top Ten</a> web security risks. SQL injection is when a user is able to manipulate a value which is used unsafely inside a SQL query. This can lead to data leaks, data loss, elevation of privilege, and other unpleasant outcomes.</p>

    <p>Brakeman focuses on ActiveRecord methods dealing with building SQL statements.</p>

    <p>A basic (Rails 2.x) example looks like this:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>User.first(:conditions =&gt; "username = '#{params[:username]}'")
    </code></pre></div></div>

    <p>Brakeman would produce a warning like this:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Possible SQL injection near line 30: User.first(:conditions =&gt; ("username = '#{params[:username]}'")) 
    </code></pre></div></div>

    <p>The safe way to do this query is to use a parameterized query:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>User.first(:conditions =&gt; ["username = ?", params[:username]])
    </code></pre></div></div>

    <p>Brakeman also understands the new Rails 3.x way of doing things (and local variables and concatentation):</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>username = params[:user][:name].downcase
    password = params[:user][:password]

    User.first.where("username = '" + username + "' AND password = '" + password + "'")
    </code></pre></div></div>

    <p>This results in this kind of warning:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Possible SQL injection near line 37:
    User.first.where((((("username = '" + params[:user][:name].downcase) + "' AND password = '") + params[:user][:password]) + "'"))
    </code></pre></div></div>

    <p>See <a href="http://guides.rubyonrails.org/security.html#sql-injection">the Ruby Security Guide</a> for more information and <a href="http://rails-sqli.org">Rails-SQLi.org</a> for many examples of SQL injection in Rails.</p>
    """
}

items["ssl_verification_bypass"] = {
    "description": """  
    <header>
        <h1 class="entry-title">SSL Verification Bypass</h1>
    </header>
    
    <p>Simply using SSL isn’t enough to ensure the data you are sending is secure. Man in the middle (MITM) attacks are well known and widely used. In some cases, these attacks rely on the client to establish a connection that doesn’t check the validity of the SSL certificate presented by the server. In this case, the attacker can present their own certificate and act as a man in the middle.</p>

    <p>In Ruby, this happens when the OpenSSL verification mode is set to <code class="highlighter-rouge">VERIFY_NONE</code></p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>require "net/https"
    require "uri"

    uri = URI.parse("https://ssl-site.com/")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Get.new(uri.request_uri)

    response = http.request(request)
    </code></pre></div></div>

    <p>In this case, if an invalid certificate was presented, no verification would occur, providing an opportunity for attack. When successful, the data transmitted (cookies, request parameters, POST bodies, etc.) would all be able to be intercepted by the MITM.</p>

    <p>Brakeman would produce a warning like this:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>SSL certificate verification was bypassed near line 24: http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    </code></pre></div></div>

    <p>To ensure that SSL verification happens use the following mode:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    </code></pre></div></div>

    <p>If the server certificate is invalid or context.ca_file is not set when verifying peers an OpenSSL::SSL::SSLError will be raised.</p>

    <p>For more information on the impact of this issue, see the paper <a href="https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf">The Most Dangerous Code in the World</a>.</p>
    """
}


items["unsafe_deserialization"] = {
    "description": """  
    <header>
    <h1 class="entry-title">Unsafe Deserialization</h1>
    </header>

    <p>Objects in Ruby may be serialized to strings. The main method for doing so is the built-in <code class="highlighter-rouge">Marshal</code> class. The <code class="highlighter-rouge">YAML</code>, <code class="highlighter-rouge">JSON</code>, and <code class="highlighter-rouge">CSV</code> libraries also have methods for dumping Ruby objects into strings, and then creating objects from those strings.</p>

    <p>Deserialization of arbitrary objects can lead to <a href="/docs/warning_types/remote_code_execution">remote code execution</a>, as was demonstrated with <a href="https://groups.google.com/d/msg/rubyonrails-security/61bkgvnSGTQ/nehwjA8tQ8EJ">CVE-2013-0156</a>.</p>

    <p>Brakeman warns when loading user input with <code class="highlighter-rouge">Marshal</code>, <code class="highlighter-rouge">YAML</code>, or <code class="highlighter-rouge">CSV</code>. <code class="highlighter-rouge">JSON</code> is covered by the checks for <a href="https://groups.google.com/d/msg/rubyonrails-security/1h2DR63ViGo/GOUVafeaF1IJ">CVE-2013-0333</a></p>
    """
}

items["unscoped_find"] = {
    "description": """
    <header>
    <h1 class="entry-title">Unscoped Find</h1>
    </header>

    <p>Unscoped <code class="highlighter-rouge">find</code> (and related methods) are a form of <a href="https://www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References">Direct Object Reference</a>. Models which belong to another model should typically be accessed via a scoped query.</p>

    <p>For example, if an <code class="highlighter-rouge">Account</code> belongs to a <code class="highlighter-rouge">User</code>, then this may be an unsafe unscoped find:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Account.find(params[:id])
    </code></pre></div></div>

    <p>Depending on the action, this could allow an attacker to access any account they wish.</p>

    <p>Instead, it should be scoped to the currently logged-in user:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>current_user = User.find(session[:user_id])
    current_user.accounts.find(params[:id])
    </code></pre></div></div>
    """
}

items["redirect"] = {
    "description": """
    <header>
    <h1 class="entry-title">Redirect</h1>
    </header>

    <p>Unvalidated redirects and forwards are #10 on the <a href="https://www.owasp.org/index.php/Top_10_2010-A10">OWASP Top Ten</a>.</p>

    <p>Redirects which rely on user-supplied values can be used to “spoof” websites or hide malicious links in otherwise harmless-looking URLs. They can also allow access to restricted areas of a site if the destination is not validated.</p>

    <p>Brakeman will raise warnings whenever <code class="highlighter-rouge">redirect_to</code> appears to be used with a user-supplied value that may allow them to change the <code class="highlighter-rouge">:host</code> option.</p>

    <p>For example,</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>redirect_to params.merge(:action =&gt; :home)
    </code></pre></div></div>

    <p>will create a warning like</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Possible unprotected redirect near line 46: redirect_to(params)
    </code></pre></div></div>

    <p>This is because <code class="highlighter-rouge">params</code> could contain <code class="highlighter-rouge">:host =&gt; 'evilsite.com'</code> which would redirect away from your site and to a malicious site.</p>

    <p>If the first argument to <code class="highlighter-rouge">redirect_to</code> is a hash, then adding <code class="highlighter-rouge">:only_path =&gt; true</code> will limit the redirect to the current host. Another option is to specify the host explicitly.</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>redirect_to params.merge(:only_path =&gt; true)

    redirect_to params.merge(:host =&gt; 'myhost.com')
    </code></pre></div></div>

    <p>If the first argument is a string, then it is possible to parse the string and extract the path:</p>

    <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>redirect_to URI.parse(some_url).path 
    </code></pre></div></div>

    <p>If the URL does not contain a protocol (e.g., <code class="highlighter-rouge">http://</code>), then you will probably get unexpected results, as <code class="highlighter-rouge">redirect_to</code> will prepend the current host name and a protocol.</p>
    """
}
