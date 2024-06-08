import 'package:post_quantum/src/core/observer/step_observer.dart';

class NullStepObserver implements StepObserver {
  @override
  List<Step> get steps => [];

  const NullStepObserver();


  @override
  void addStep({
    String? title,
    String? description,
    Map<String, Object>? parameters,
    Map<String, Object>? results
  }) {
    return;
  }

  @override
  void prettyPrint() {
    return;
  }

}