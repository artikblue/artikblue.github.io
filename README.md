# Horace Jekyll Theme v1.2.0

[Theme Live Demo](https://horace.netlify.com/)

## Features

* Mobile-ready
* Contact form built-in 
* Social icons built-in
* Social sharing built-in
* Mailchimp subscription form
* Free images pack for your blog cover
* Code Syntax Highlight with [Prism.js](https://prismjs.com/)
* Support for Disqus comments

## Getting Started

**Table of Contents**

* 1. Theme Configuration
* 2. Author configuration
* 3. Contact form setings
* 4. Social Links
* 5. Site Navigation
* 6. Images
* 7. Local Installation
* 8. Deployment
* 9. Support

### 1. Theme Configuration

The theme configuration options can be found within the **_config.yml** file. More information about Jekyll configuration can be found in the Jekyll documentation.

* description - the description of your site for social meta tag, search engines, and feed.xml.
* name - the title of your blog, shown in the page and description areas.
* logo - the image for site logo.
* favicon - the icon for your site.
* baseurl - the subpath of your site, e.g. /blog, for generating urls. If baseurl is set, you will need to prepend the baseurl to these settings: author image, site navigation, post images.
* production_url - the base hostname and protocol of your site for where absolute urls are needed.
* disqus - your Disqus shortname. Enter the Disqus shortname here if you wish to have Disqus comments enabled, leave blank to disable comments.
* mailchimp_url - your form action URL for MailChimp newsletter signup form.
* cover_image - the cover image used for you site home page.

### 2. Author configuration

* name - the name of the post/blog author.
* image - the author profile image, shown at the bottom of each post and in the intro section on the home page. The author image can be found in the horace/assets/images/authorimage.jpg location.
* greetings - used in the home page for the author intro section.
* description - used in the home page for the author intro section.
* bio - the author biography shown at the bottom of each post.

### 3. Contact form setings
To make contact form work make sure you have defined "email: youremail@email.com" in _config.yml file and verify your form on formspree.io.

* email - email used for contact form.
* contact_page_description: - description used in contact form page (contact.html).
* thankyou_page_description - description used in thank you page (thank-you.html).

### 4. Social Links

To enable social links on your blog simply enter your social profile username, for example, twitter: "justgoodthemes" . If a field is left blank, the social icon will not be shown.

### 5. Site Navigation

The site navigation can be found in the **_config.yml** file. To add a page to the site navigation simply add your new page in the markdown format (e.g. newpage.md) in the theme root folder. Next edit your navigation menu located in **_config.yml** file on line 26. To add a new item to the navigation you have to add the item name and url. For example:

~~~~
navigation:
- text: New Page
url: /newpage/
~~~~

### 6. Images

Images for pages are located in the horace/assets/images folder and images for posts are located in the horace/assets/images/posts directory.

#### Image With Caption

Within your blog posts you can include captions for images. This requires using some HTML markup.

The example below illustrates how to include an image with a caption in a blog post:

~~~~
{% include image-caption.html imageurl="/images/posts/Apple-Watch-In-Car.jpg" 
title="Apple Super" caption="supertest" %}
~~~~

Add the following code into your post/page markdown and change its attributes accordingly.

#### Full Width Image With Caption

To have wide images in posts or pages simply add #wide word with the hashtag at the end of image path like in the example below:

~~~~
{% include image-caption.html imageurl="/images/posts/Apple-Watch-In-Car.jpg#wide" 
title="Apple" caption="This is caption" %}
~~~~

Add the following code into your post/page markdown and change its attributes accordingly.

#### Image alignment

To align images left or right you have to use #left and #right words with the hashtag at the end of the image path. Please, check the example below:

~~~~
![My helpful screenshot]("/assets/screenshot.jpg#left")
~~~~

### 7. Local Instalation

To set up Jekyll on local machine please follow the official documentation that can be found here -> https://jekyllrb.com/docs/.

### 8. Deployment

Sites built using Jekyll can be deployed in a large number of ways due to the static nature of the generated output. Here are some of the most common ways:

#### Manual Deployment

Jekyll generates your static site to the **_site** directory by default. You can transfer the contents of this directory to almost any hosting provider to get your site live. Here are some manual ways of achieving this:

##### Netlify

This theme is prepared to be hosted on [Netlify](https://www.netlify.com/). All you need to do is create a new private repository on GitHub or GitLab. Upload the theme to the repository and link your repo to Netlify. Please check [this link](https://www.netlify.com/blog/2015/10/28/a-step-by-step-guide-jekyll-3.0-on-netlify/#step-2-link-to-your-github) with the step by step guidelines.

##### FTP

Most traditional web hosting providers let you upload files to their servers over FTP. To upload a Jekyll site to a web host using FTP, run the jekyll build command and copy the contents of the generated **_site** folder to the root folder of your hosting account. This is most likely to be the httpdocs or public_html folder on most hosting providers.

##### Amazon S3

If you want to host your site on Amazon S3, you can do so by using the [s3_website application](https://github.com/laurilehmijoki/s3_website). It will push your site to Amazon S3 where it can be served like any web server, dynamically scaling to almost unlimited traffic.

### 9. Support

The documentation included provides all the information you need to get started with the theme. However, if you have any questions you can email us at hello@justgoodthemes.com, and we will be happy to help you.

*Also, if you have any bug reports, or feature requests, please let us know!*
