import React from 'react';
import ReactDOM from 'react/lib/ReactDOM';
import isEqual from 'lodash.isequal';
import assign from 'lodash.assign';
import Component from '../components/base';

// used in the DragDropSupport below
function start(drag) {
  // drag.info.type: "libraryitem", "gridcell",...?
  //console.log('dnd start', drag);
  let type = drag.info.type;
  let shouldAccept = this.accept[type] &&
   'function' == typeof this.accept[type] ? this.accept[type].call(this, drag) : this.accept[type];

  //console.log('dnd should accept', shouldAccept);
  if(shouldAccept) {
    // Accept object with the following spec:
    // prio : 1,
    // targetRect : rect,
    // drawRect : rect,
    // cellRect : rect,
    // drop : dropFn(splitCell, sheet)
    drag.registerDropRect(this);
    this.setupDragDropRect && this.setupDragDropRect();
  }
}

function end() {
  //console.log('end drag drop');
}

/**
* @params spec - sense drag and drop specification object:
* accept(info) {}
* start(info) {}
* enter(info) {}
* leave(info) {}
* end(info) {}
* drop(info) {}
* placeClassName - the element class name where sense object should be injected
* onDropGridCellHandler(item) - grid cell drop handler
* onDropLibraryItemHandler(item) - libraryitem drop handler
*/
export default function DragDropSupport(spec = {}) {
  return function AddDragDropSupport(DecorateComponent) {
    const displayName =
     DecorateComponent.displayName ||
     DecorateComponent.name ||
     'Component';

    class DragDropContainer extends Component {
      constructor(props) {
        super(props);
        this.state = {
          isObjectInjected: false,
          itemid: null, // item id
          item: null, // dropped item info
          object: null, // injected sense object
          accept: {
            libraryitem: true,
            gridcell: true
          }
        }

        // qlik services. see component.js
        this.qlikDragDropService = props.layout.services.qlikDragDropService;
        this.qlik = props.layout.services.qlik;

        this.DecoratedComponent = DecorateComponent;
        this.displayName = `DragDropContainer > ${displayName}`;

        // accept only objects of specified type
        this.accept = {
          libraryitem: () => { return this.state.accept.libraryitem },
          gridcell: () => { return this.state.accept.gridcell }
        };

        // drop handlers
        let dropGridCellHandler = this.onDropGridCellHandler;
        if (!dropGridCellHandler)
          // default dropgridcell handler
          dropGridCellHandler = (item) => {
            console.log(item);
            this.setState( { item: item, itemid: item.cell.id } );
          };

        let dropLibraryItemHandler = this.onDropLibraryItemHandler;
        if (!dropLibraryItemHandler)
          // default libraryitem drop handler
          dropLibraryItemHandler = (item) => {
            console.log(item);
            this.setState( { item: item, itemid: item.item.id } );
          };

        this.drop = {
          gridcell: dropGridCellHandler,
          libraryitem: dropLibraryItemHandler
        };

        // priority
        this.prio = 1;
        // start, end ... methods for DnD support
        this.start = start.bind(this);
        this.end = end.bind(this);
      }

      setAcceptTo(value) {
        this.setState({
          accept: {
            libraryitem: value,
            gridcell: value
          }
        })
      }

      componentDidMount() {
        let self = this;
        let element = ReactDOM.findDOMNode(this);
        $(element).draggable({
          start() {
            self.setAcceptTo(false);
          },
          stop() {
            console.log('drag stop');
            self.setupDragDropRect();
            self.setAcceptTo(true);
          }
        });
        $(element).resizable({
          start() {
            self.setAcceptTo(false);
          },
          stop() {
            console.log('resize stop');
            self.setupDragDropRect();
            self.setAcceptTo(true);
          }
        });

        if(this.qlikDragDropService) {
          this.setupDragDropRect();
          this.qlikDragDropService.registerDropTarget(this);
        }
        this.injectObject();
      }

      componentWillUnmount() {
        this.removeObject();
        console.log('WillUnmount');
        if(this.qlikDragDropService) {
          this.qlikDragDropService.unregisterDropTarget(this);
        }

        this.targetRect = null;
        this.drawRect = null;
        this.cellRect = null;
      }

      componentDidUpdate() {
        this.injectObject();
        this.repaintObject();
      }

      render() {
        const DecoratedComponent = this.DecoratedComponent;
        return <DecoratedComponent {...this.props} item={this.state.item} />;
      }

      // Drag and drop support methods and props
      // "libraryitem", "gridcell",...?
      getRect(){
        //console.log(this.child);
        console.log('get rect');
        let element = ReactDOM.findDOMNode(this);
        let br = element.getBoundingClientRect();
        console.log(br);
        console.warn('можно передавать параметр в spec, ссылку на контейнер');
        let $parent = $(element).parent();
        console.log('parent', $parent);
        //React.findDOMNode(this.refs.child).getBoundingClientRect();
        return {
          left: br.left - $parent.scrollLeft(),
          top: br.top - $parent.scrollTop(),
          right: (br.right - $parent.scrollLeft()) || (br.left - $parent.scrollLeft() + br.width),
          bottom: (br.bottom - $parent.scrollTop()) || (br.top - $parent.scrollTop() + br.height)
        }
      }

      setupDragDropRect() {
        // see render
        let r = this.getRect();

        this.targetRect = r;
        this.drawRect = r;
        this.cellRect = r;
      }

      getPlaceholderElement() {
        let element = ReactDOM.findDOMNode(this);
        let placeholder = element.getElementsByClassName(this.placeClassName || "placeholder")[0];
        if(!placeholder) placeholder = element;
        return element;
      }

      injectObject(){
        if(!this.state.isObjectInjected && this.state.itemid) {
          let id = this.state.itemid;
          this.removeObject();
          let placeElement = this.getPlaceholderElement();
          if(placeElement) {
            this.qlik.currApp().getObject(placeElement, id).then((object) => {
              this.setState({ object: object,  isObjectInjected: true});
              //this.qlik.resize(id);
            });
          }
        }
      }

      repaintObject(){
        let r = this.getRect();
        if(!isEqual(this.cellRect, r)) {
          this.setupDragDropRect();
          if(this.state.object)
            this.qlik.resize(this.state.object);
        }
      }

      removeObject(){
        if(this.state.object) {
          this.state.object.close();
          this.setState({object: null, isObjectInjected: false});
          //let placeElement = this.getPlaceholderElement();
          //if(placeElement) placeElement.innerHTML = '';
        }
      }
    }

    // assign sense dnd support method
    assign(DragDropContainer.prototype, spec);

    return DragDropContainer;
  }
}
