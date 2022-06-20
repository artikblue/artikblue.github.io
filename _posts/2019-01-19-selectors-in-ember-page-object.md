---
layout: post
title:  Selectors in Ember Page Object
date:   2019-01-19 15:01:35 -0700
image:  '/images//emberjs_daily.png'
tags:   Ember.js Testing Patterns JavaScript
---
## Selectors in Ember Page Object
[Ember CLI Page Object](http://ember-cli-page-object.js.org/docs/v1.15.x/) is a fantastic addon. It's an implementation of [Page Object Pattern](http://blog.josephwilk.net/cucumber/page-object-pattern.html) for acceptance testing in Ember. The usage of the addon in your Ember project is a good thing by itself. But there are a couple of small tricks that can make the experience even more delightful, and I'd like to share them with you.

### Using of ember-test-selectors
How many times did you struggle coming up with a particular CSS selector to target a certain DOM element in your tests? If you'd been like me, than probably many times. There's a cure for that, and it's called [ember-test-selectors](https://github.com/simplabs/ember-test-selectors). The idea is simple: you just assign HTML data attributes that start with *data-test-* prefix (e.g. "data-test-button="true"") to elements you would like to target, and then use them as selectors in your tests. And you ask "What **ember-test-selectors** is doing then?". Sure, it removes those attributes during production builds from HTML markup preventing it's cluttering with unnecessary data. So you can just let your imagination fly assigning those attributes and don't really bother that there's going to be a mess in HTML when it's delivered to the end user. There are a couple of other cool features of this addon, feel free to check them out in [README](https://github.com/simplabs/ember-test-selectors).

If you are using *ember-test-selectors*, your page object file (module) may look like this:

```javascript
import {
  clickable,
  is,
  text
} from 'ember-cli-page-object';


export default create({
  visit: visitable('/todos'),
  firstTodoItemText: text('[data-test-todo-item]:nth-child(1)'),
  secondTodoItemText: text('[data-test-todo-item]:nth-child(2)'),
  todoItemText: text('[data-test-todo-item]'),
  countOfTodos: count('[data-test-todo-item]'),
  clickAddTodo('[data-test-add-todo]'),
  addTodoIsDisabled: is(':disabled', '[data-test-add-todo]')
});
```
That's okay, but there's a repetition with selectors strings. And it's a violation of [DRY](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself).

## Selectors Object
The scenario above is where *Selectors Object* pattern (maybe too small to be called a "pattern", but still) becomes handy. We're going to extract selector's strings to a separate JavaScript object, and reference it in our page object's properties. Here's an updated version:
```javascript
import {
  clickable,
  is,
  text
} from 'ember-cli-page-object';

let selectors = {
  addTodoButton: '[data-test-add-todo]',
  singleTodoItem: '[data-test-todo-item]',

  todoItem(nth) {
   return `${this.singleTodoItem}:nth-child(${nth})`;
  }
};

export default create({
  visit: visitable('/todos'),
  firstTodoItemText: text(selectors.todoItem(1)),
  secondTodoItemText: text(selectors.todoItem(2)),
  countOfTodos: count(selectors.singleTodoItem),
  clickAddTodo(selectors.addTodoButton),
  addTodoIsDisabled: is(':disabled', selectors.addTodoButton)
});
```
The basic rules I encourage to follow creating *Selectors* POJOs are:

1) **Don't abuse parameters**. Maybe all you need is just [options.multiple](http://ember-cli-page-object.js.org/docs/v1.15.x/api/text).
```javascript
export default create({
  ...
  todoItem: text(selectors.singleTodoItem, { multiple: true })
});
```
And then in your tests you just access via `[]` the item you need.

2) **Avoid using fancy CSS selectors rules**. It's so tempting to start using CSS nesting rules, but I would recommend keeping selectors structure as flat as possible and just come up with an additional `data-test-*` selector to target a particular element. Moreover you can use interpolation syntax for test selectors attribute values in your templates, and `ember-test-selectors` will [take care of it](https://github.com/simplabs/ember-test-selectors#usage) too.
```handlebars
<table>
  <tr>
    <th scope="col">Name</th>
    <th scope="col">Title</th>
  </tr>
  {{#each rows as |row i|}}
    <tr>
      <td data-test-employees-name="{{inc i}}">row.name</td>
      <td data-test-employees-title="{{inc i}}">row.title</td>
    </tr>
  {{/each}}
</table>
```
* `inc` is coming from [ember-composable-helpers](https://github.com/DockYard/ember-composable-helpers#math-helpers)

Selectors:
```javascript
let selectors = {
  employeesName(nth) {
    return `[data-test-employees-name="${nth}"]`;
  },
  employeesTitle(nth) {
    return `[data-test-employees-title="${nth}"]`;
  }
};
```
Instead of having something like this:
```javascript
let selectors = {
  employeesName(nth) {
    return `[data-test-employee-row]:nth-chold(${nth}) [data-test-employees-name]`;
  },
  ...
};
```
*This rule decouples your page object and selectors from the HTML structure of the page and makes your tests more refactoring-resilient because of that.*

3) **Keep selectors object private**. Your public interface should be your page object, if you need some selector to be exposed, think about making it part of page object first (maybe a method on page object?), instead of just doing `export let selectors`.

4) **Don't be afraid of having numerous Selectors Objects**. If your page can be divided in a couple of separate logical pieces, you can create a separate *Selectors Object* for each piece, keeping a single *Page Object* that consolidates all of them.

## Conclusion
*Selectors Object* pattern is a simple but powerful tool, that can make your tests cleaner, more refactoring-resilient and just easier to reason about.
