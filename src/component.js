import loadCSS from './loadcss';

const global = window;
const define = (window && window.define) || define;
const dependencies = ['module', 'js/qlik'];

define(dependencies,
  function(module, qlik){
    console.log('load!', qlik);
    const ROOT_URI = module.uri.split('/').slice(0, -1).join('/');
    const DEPENDENCIES_TO_LOAD = {
      React: `${ROOT_URI}/vendors/react.min`
    };
    loadCSS(`${ROOT_URI}/styles.css`);

    let initialProperties = require('./initialProperties');
    let definition = require('./definition');
    let {lazyLoader, isDependeciesLoaded} = require('./lazyLoad');
    let paintMethod = require('./paint');

    const injectAndCallPaintMethod = function(context, method, ...args) {
          context.paint = method;
          context.paint(...args);
    };
    // load into the global context required libraries using provided "map" object
    const lazyLoad = lazyLoader(global,
      global.require,
      DEPENDENCIES_TO_LOAD,
      injectAndCallPaintMethod);

    let paint = function ($element, layout) {
      let self = this;
      if(!isDependeciesLoaded(global, DEPENDENCIES_TO_LOAD))
        lazyLoad(self, paintMethod, $element, layout);
      else
        injectAndCallPaintMethod(self, paintMethod, $element, layout);
    };

    return {
      initialProperties,
      definition,
      paint
    }
  }
);
